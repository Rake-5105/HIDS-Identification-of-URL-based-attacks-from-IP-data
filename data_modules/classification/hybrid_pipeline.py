from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .ml_classifier import ATTACK_CLASSES, predict_with_model, save_model, train_multiclass_model
from .regex_detector import detect_regex_attack
from .statistical_detector import add_statistical_flags


def _resolve_url_column(df: pd.DataFrame) -> str:
    if "url" in df.columns:
        return "url"
    if "full_url" in df.columns:
        return "full_url"
    raise KeyError("Expected 'url' or 'full_url' column in dataset")


def _final_class(
    regex_class: str,
    ml_class: str,
    ml_confidence: float,
    stat_suspicious: int,
    stat_is_bruteforce: int,
) -> str:
    if regex_class != "Normal":
        return regex_class

    if stat_is_bruteforce == 1:
        return "Credential Stuffing / Brute Force"

    if stat_suspicious == 1:
        return "Suspicious Behavior"

    if ml_class in ATTACK_CLASSES and ml_confidence >= 0.55:
        return ml_class

    return "Normal"


def run_hybrid_detection(
    input_csv: str = "output/url_feature_dataset.csv",
    output_dir: str = "output",
) -> dict:
    input_path = Path(input_csv)
    if not input_path.exists():
        raise FileNotFoundError(f"Input dataset not found: {input_csv}")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path)
    url_col = _resolve_url_column(df)

    regex_results = df[url_col].apply(detect_regex_attack)
    df["regex_class"] = regex_results.apply(lambda x: x[0])
    df["regex_pattern"] = regex_results.apply(lambda x: x[1])

    artifacts = train_multiclass_model(df, url_col=url_col)
    ml_labels, ml_conf = predict_with_model(df, artifacts)
    df["ml_class"] = ml_labels
    df["ml_confidence"] = ml_conf.round(4)

    df = add_statistical_flags(df)

    df["final_classification"] = df.apply(
        lambda row: _final_class(
            regex_class=str(row["regex_class"]),
            ml_class=str(row["ml_class"]),
            ml_confidence=float(row["ml_confidence"]),
            stat_suspicious=int(row["stat_suspicious"]),
            stat_is_bruteforce=int(row.get("stat_is_bruteforce", 0)),
        ),
        axis=1,
    )

    result_path = out_dir / "module4_hybrid_results.csv"
    df.to_csv(result_path, index=False)

    report_path = out_dir / "module4_ml_report.txt"
    report_path.write_text(artifacts.report_text, encoding="utf-8")

    model_path = save_model(artifacts, output_dir=str(out_dir))

    suspicious_ips = []
    if "source_ip" in df.columns:
        suspicious_ips = (
            df.loc[df["stat_suspicious"] == 1, "source_ip"]
            .astype(str)
            .drop_duplicates()
            .tolist()
        )

    summary = {
        "rows": int(len(df)),
        "class_counts": df["final_classification"].value_counts().to_dict(),
        "regex_detected": int((df["regex_class"] != "Normal").sum()),
        "statistical_suspicious_rows": int(df["stat_suspicious"].sum()),
        "suspicious_ips": suspicious_ips,
        "ml_accuracy": round(float(artifacts.accuracy), 4),
        "output_csv": str(result_path),
        "ml_report": str(report_path),
        "model_path": model_path,
    }

    summary_path = out_dir / "module4_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return summary
