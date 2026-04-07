import argparse
import json
import os
import re
import sys
from datetime import datetime

import pandas as pd

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from data_modules.classification import run_hybrid_detection
from data_modules.classification.regex_detector import detect_regex_attack
from data_modules.data_collection import CollectionConfig, DataCollector
from data_modules.data_collection.models import LogSource, URLRequest
from data_modules.feature_extraction.url_features import extract_features
from data_modules.url_parsing import URLParsingPipeline


def _row_from_parsed(parsed):
    url_value = parsed.raw_url or parsed.path or ""
    return {
        "timestamp": parsed.timestamp.isoformat() if parsed.timestamp else "",
        "source_ip": parsed.source_ip,
        "method": parsed.method,
        "url": url_value,
        "full_url": url_value,
        "status_code": parsed.status_code,
        "user_agent": parsed.user_agent,
        "referrer": parsed.referrer,
        "scheme": parsed.scheme,
        "host": parsed.host,
        "path": parsed.path,
        "query_string": parsed.query_string,
        "file_extension": parsed.file_extension,
        "source": parsed.source,
    }


def _row_from_request(req):
    url_value = req.full_url or req.path or ""
    return {
        "timestamp": req.timestamp.isoformat() if req.timestamp else "",
        "source_ip": req.source_ip,
        "method": req.method,
        "url": url_value,
        "full_url": url_value,
        "status_code": req.status_code,
        "user_agent": req.user_agent,
        "referrer": req.referrer,
        "scheme": "",
        "host": req.host,
        "path": req.path,
        "query_string": req.query_string,
        "file_extension": "",
        "source": req.source.value if hasattr(req.source, "value") else str(req.source),
    }


def _build_module3_dataset(collection_result, parse_result):
    rows = [_row_from_parsed(item) for item in parse_result.parsed_urls]

    if not rows:
        rows = [_row_from_request(item) for item in collection_result.url_requests]

    dataset = pd.DataFrame(rows)
    if dataset.empty:
        return dataset

    feature_rows = dataset["url"].fillna("").apply(extract_features)
    feature_df = pd.json_normalize(feature_rows.tolist())
    return pd.concat([dataset, feature_df], axis=1)


def _csv_fallback_url_requests(input_path):
    if not str(input_path).lower().endswith('.csv'):
        return []

    try:
        df = pd.read_csv(input_path)
    except Exception:
        return []

    normalized_cols = {str(col).strip().lower(): col for col in df.columns}
    url_col = None
    for candidate in ('url', 'full_url', 'request_url', 'uri', 'path'):
        if candidate in normalized_cols:
            url_col = normalized_cols[candidate]
            break

    if not url_col:
        return []

    requests = []
    for _, row in df.iterrows():
        url_value = str(row.get(url_col, '') or '').strip()
        if not url_value:
            continue

        source_ip_col = normalized_cols.get('source_ip')
        method_col = normalized_cols.get('method')
        timestamp_col = normalized_cols.get('timestamp')
        status_code_col = normalized_cols.get('status_code')
        user_agent_col = normalized_cols.get('user_agent')
        referrer_col = normalized_cols.get('referrer')

        source_ip = str(row.get(source_ip_col, '0.0.0.0') or '0.0.0.0')
        method = str(row.get(method_col, 'GET') or 'GET').upper()

        ts_raw = row.get(timestamp_col)
        timestamp = pd.Timestamp.utcnow().to_pydatetime().replace(tzinfo=None)
        if ts_raw is not None and str(ts_raw).strip() != '':
            parsed_ts = pd.to_datetime(ts_raw, errors='coerce')
            if pd.notna(parsed_ts):
                timestamp = parsed_ts.to_pydatetime().replace(tzinfo=None)

        status_code = row.get(status_code_col)
        try:
            if status_code is None or not pd.notna(status_code):
                status_code = None
            else:
                status_code = int(float(status_code))
        except Exception:
            status_code = None

        requests.append(
            URLRequest(
                source_ip=source_ip,
                timestamp=timestamp,
                full_url=url_value,
                method=method,
                status_code=status_code,
                user_agent=str(row.get(user_agent_col, '') or '') or None,
                referrer=str(row.get(referrer_col, '') or '') or None,
                source=LogSource.IPDR,
            )
        )

    return requests


def _raw_text_fallback_url_requests(input_path):
    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as fh:
            content = fh.read(1024 * 1024)
    except Exception:
        return []

    if not content.strip():
        return []

    # Match full URLs first, then path-like URLs often present in logs.
    full_urls = re.findall(r'https?://[^\s"\'<>]+', content, flags=re.IGNORECASE)
    path_urls = re.findall(r'(?<![A-Za-z0-9])/[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+', content)

    candidates = []
    seen = set()
    for raw in full_urls + path_urls:
        cleaned = str(raw).strip().strip('.,;')
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        candidates.append(cleaned)
        if len(candidates) >= 200:
            break

    now = pd.Timestamp.utcnow().to_pydatetime().replace(tzinfo=None)
    return [
        URLRequest(
            source_ip='0.0.0.0',
            timestamp=now,
            full_url=url,
            method='GET',
            status_code=None,
            user_agent=None,
            referrer=None,
            source=LogSource.IPDR,
        )
        for url in candidates
    ]


def _compose_summary(module4_df, module4_summary):
    class_col = "final_classification" if "final_classification" in module4_df.columns else None

    if class_col:
        class_counts = module4_df[class_col].astype(str).value_counts().to_dict()
        threat_mask = module4_df[class_col].astype(str).str.lower() != "normal"
        threats_detected = int(threat_mask.sum())
    else:
        class_counts = module4_summary.get("class_counts", {})
        threats_detected = int(
            sum(count for label, count in class_counts.items() if str(label).lower() != "normal")
        )

    total_requests = int(len(module4_df))
    threat_percentage = round((threats_detected / total_requests) * 100, 1) if total_requests else 0.0

    return {
        "total_requests": total_requests,
        "threats_detected": threats_detected,
        "threat_percentage": threat_percentage,
        "classification_breakdown": class_counts,
        "suspicious_ips": module4_summary.get("suspicious_ips", []),
        "ml_accuracy": module4_summary.get("ml_accuracy", 0.0),
        "analyzed_at": datetime.now().isoformat(),
    }


def _run_module4_with_fallback(module3_df, module3_csv, output_dir):
    try:
        module4_summary = run_hybrid_detection(input_csv=module3_csv, output_dir=output_dir)
        module4_csv = module4_summary["output_csv"]
        module4_df = pd.read_csv(module4_csv)
        return module4_df, module4_summary
    except Exception as exc:
        fallback_df = module3_df.copy()

        url_col = 'url' if 'url' in fallback_df.columns else 'full_url'
        regex_results = fallback_df[url_col].fillna('').astype(str).apply(detect_regex_attack)
        fallback_df['regex_class'] = regex_results.apply(lambda x: x[0])
        fallback_df['regex_pattern'] = regex_results.apply(lambda x: x[1])
        fallback_df['final_classification'] = fallback_df['regex_class']

        fallback_csv = os.path.join(output_dir, 'module4_hybrid_results.csv')
        fallback_df.to_csv(fallback_csv, index=False)

        class_counts = fallback_df['final_classification'].astype(str).value_counts().to_dict()
        suspicious_ips = []
        if 'source_ip' in fallback_df.columns:
            suspicious_ips = (
                fallback_df.loc[
                    fallback_df['final_classification'].astype(str).str.lower() != 'normal',
                    'source_ip'
                ]
                .astype(str)
                .drop_duplicates()
                .tolist()
            )

        fallback_summary = {
            'rows': int(len(fallback_df)),
            'class_counts': class_counts,
            'regex_detected': int((fallback_df['regex_class'].astype(str).str.lower() != 'normal').sum()),
            'statistical_suspicious_rows': 0,
            'suspicious_ips': suspicious_ips,
            'ml_accuracy': 0.0,
            'output_csv': fallback_csv,
            'ml_report': '',
            'model_path': '',
            'fallback_reason': str(exc),
        }

        summary_path = os.path.join(output_dir, 'module4_summary.json')
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(fallback_summary, f, indent=2)

        return fallback_df, fallback_summary


def run_pipeline(input_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    config = CollectionConfig(
        output_directory=output_dir,
        log_level="WARNING",
        log_file=None,
    )

    collector = DataCollector(config=config)
    collection_result = collector.collect(source=input_path)
    collector.save(collection_result, tag="dashboard")

    if not collection_result.url_requests:
        collection_result.url_requests = _csv_fallback_url_requests(input_path)

    if not collection_result.url_requests:
        collection_result.url_requests = _raw_text_fallback_url_requests(input_path)

    if not collection_result.url_requests:
        raise ValueError("No URL requests were extracted from the uploaded file")

    parsing_pipeline = URLParsingPipeline(normalize=True)
    parse_result = parsing_pipeline.run(collection_result, tag="dashboard")
    parsing_pipeline.save(parse_result, output_dir=output_dir, tag="dashboard")

    module3_df = _build_module3_dataset(collection_result, parse_result)
    if module3_df.empty:
        raise ValueError("No rows available for Module 3 feature extraction")

    module3_csv = os.path.join(output_dir, "url_feature_dataset.csv")
    module3_df.to_csv(module3_csv, index=False)

    module4_df, module4_summary = _run_module4_with_fallback(module3_df, module3_csv, output_dir)
    module4_csv = module4_summary["output_csv"]

    summary = _compose_summary(module4_df, module4_summary)

    payload = {
        "summary": summary,
        "artifacts": {
            "module3_csv": module3_csv,
            "module4_csv": module4_csv,
            "module4_summary_json": os.path.join(output_dir, "module4_summary.json"),
            "module4_model": module4_summary.get("model_path", ""),
        },
        "module1": {
            "http_log_entries": len(collection_result.http_logs),
            "ipdr_records": len(collection_result.ipdr_records),
            "url_requests": len(collection_result.url_requests),
        },
        "module2": parse_result.summary(),
        "module3": {
            "rows": int(len(module3_df)),
        },
        "module4": {
            "rows": int(module4_summary.get("rows", len(module4_df))),
            "regex_detected": int(module4_summary.get("regex_detected", 0)),
            "statistical_suspicious_rows": int(module4_summary.get("statistical_suspicious_rows", 0)),
        },
    }

    print(json.dumps(payload))


def main():
    parser = argparse.ArgumentParser(description="Run modules 1-4 for dashboard uploads")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    run_pipeline(input_path=args.input, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
