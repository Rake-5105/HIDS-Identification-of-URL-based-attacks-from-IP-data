"""
Log Ingestion Pipeline.
Orchestrates ingestion of external log files (HTTP access logs, IPDR CSV/TSV,
PCAP captures) from a specified source path or from structured config directories.
Saves results to JSON and/or CSV output files.
"""

import csv
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

from .models import CollectionResult, HTTPLogEntry, IPDRRecord, URLRequest, SnortAlert
from .config import CollectionConfig
from .log_parser import HTTPLogParser
from .ipdr_collector import IPDRCollector
from .pcap_analyzer import PCAPAnalyzer
from .snort_collector import SnortCollector

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# File-type sniffer
# ─────────────────────────────────────────────────────────────────────────────

def _detect_file_type(filepath: str) -> str:
    """
    Return 'pcap', 'ipdr', 'log', or 'unknown' based on extension
    and a quick content peek.
    """
    ext  = os.path.splitext(filepath)[1].lower()
    name = os.path.basename(filepath).lower()
    if ext in (".pcap", ".pcapng", ".cap"):
        return "pcap"
    # Snort alert files: named 'alert', 'snort.alert', or any *.alert
    if name == "alert" or ext == ".alert" or "snort" in name:
        return "snort"
    if ext in (".csv", ".tsv"):
        # Quick peek: if it looks like a Snort CSV, classify accordingly
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as _f:
                first = _f.readline().lower()
            if "sig_id" in first or "sig_generator" in first or "srcport" in first:
                return "snort"
        except Exception:
            pass
        return "ipdr"
    if ext in (".log", ".txt", ".gz", ".bz2", ".zip"):
        return "log"
    # Peek at first bytes for PCAP magic numbers
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x0a\x0d\x0d\x0a"):   # pcapng
            return "pcap"
    except Exception:
        pass
    return "log"  # default assumption


# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def _save_json(data: list, filepath: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Saved JSON → %s (%d records)", filepath, len(data))


def _save_csv(data: list, filepath: str) -> None:
    if not data:
        return
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    fieldnames = list(data[0].keys())
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)
    logger.info("Saved CSV  → %s (%d records)", filepath, len(data))


# ─────────────────────────────────────────────────────────────────────────────
# Main Ingestion Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class LogIngestionPipeline:
    """
    High-level ingestion pipeline.

    Usage:
        pipeline = LogIngestionPipeline(config)
        result   = pipeline.ingest_path("/path/to/directory_or_file")
        pipeline.save_results(result)
    """

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config        = config or CollectionConfig()
        self.log_parser    = HTTPLogParser(self.config)
        self.ipdr_coll     = IPDRCollector(self.config)
        self.pcap_analyzer = PCAPAnalyzer(self.config)
        self.snort_coll    = SnortCollector(self.config)

    # ── Ingest a single file ─────────────────────────────────────────────

    def ingest_file(self, filepath: str) -> CollectionResult:
        """Auto-detect and ingest a single file."""
        result = CollectionResult(source_files=[filepath])
        ftype  = _detect_file_type(filepath)
        logger.info("Ingesting file: %s  [detected: %s]", filepath, ftype)

        try:
            if ftype == "pcap":
                reqs, entries = self.pcap_analyzer.analyze_file(filepath)
                result.url_requests.extend(reqs)
                result.http_logs.extend(entries)

            elif ftype == "snort":
                snort_alerts = self.snort_coll.parse_file(filepath)
                result.snort_alerts.extend(snort_alerts)

            elif ftype == "ipdr":
                records = self.ipdr_coll.parse_file(filepath)
                result.ipdr_records.extend(records)

            else:  # "log" or unknown
                entries, reqs = self.log_parser.parse_file(filepath)
                result.http_logs.extend(entries)
                result.url_requests.extend(reqs)

        except Exception as exc:
            msg = f"Error ingesting {filepath}: {exc}"
            logger.error(msg)
            result.errors.append(msg)

        return result

    # ── Ingest a directory ───────────────────────────────────────────────

    def ingest_directory(self, directory: str) -> CollectionResult:
        """Recursively scan a directory and ingest all supported files."""
        result = CollectionResult()
        if not os.path.isdir(directory):
            logger.error("Directory not found: %s", directory)
            result.errors.append(f"Directory not found: {directory}")
            return result

        supported_exts = (
            set(self.config.log_extensions)
            | set(self.config.pcap_extensions)
            | set(self.config.snort_extensions)
            | {".csv", ".tsv"}
        )

        for root, _, files in os.walk(directory):
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in supported_exts:
                    continue
                fpath = os.path.join(root, fname)
                sub   = self.ingest_file(fpath)
                result.http_logs.extend(sub.http_logs)
                result.ipdr_records.extend(sub.ipdr_records)
                result.url_requests.extend(sub.url_requests)
                result.snort_alerts.extend(sub.snort_alerts)
                result.errors.extend(sub.errors)
                result.source_files.append(fpath)

        # Correlate IPDR with URL counts from parsed logs
        if result.ipdr_records and result.url_requests:
            logger.info("Correlating IPDR records with URL requests…")
            result.ipdr_records = self.ipdr_coll.correlate_with_urls(
                result.ipdr_records, result.url_requests
            )

        return result

    # ── Ingest either path type ──────────────────────────────────────────

    def ingest_path(self, path: str) -> CollectionResult:
        """Ingest a file or directory. Returns a CollectionResult."""
        if os.path.isfile(path):
            return self.ingest_file(path)
        elif os.path.isdir(path):
            return self.ingest_directory(path)
        else:
            logger.error("Path does not exist: %s", path)
            result = CollectionResult()
            result.errors.append(f"Path does not exist: {path}")
            return result

    # ── Ingest from configured default directories ────────────────────────

    def ingest_defaults(self) -> CollectionResult:
        """
        Ingest from the configured log_directory and pcap_directory.
        """
        self.config.ensure_directories()
        combined = CollectionResult()

        directories = [
            self.config.log_directory,
            self.config.pcap_directory,
            self.config.snort_directory,
        ]
        for directory in directories:
            res = self.ingest_directory(directory)
            combined.http_logs.extend(res.http_logs)
            combined.ipdr_records.extend(res.ipdr_records)
            combined.url_requests.extend(res.url_requests)
            combined.snort_alerts.extend(res.snort_alerts)
            combined.errors.extend(res.errors)
            combined.source_files.extend(res.source_files)

        return combined

    # ── Save results ─────────────────────────────────────────────────────

    def save_results(self, result: CollectionResult,
                     tag: str = "") -> Dict[str, str]:
        """
        Persist collection results to JSON and/or CSV in output_directory.
        Returns a dict of {data_type: saved_filepath}.
        """
        out_dir = self.config.output_directory
        os.makedirs(out_dir, exist_ok=True)

        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"{tag}_" if tag else ""
        paths: Dict[str, str] = {}

        datasets = [
            ("http_logs",    [e.to_dict() for e in result.http_logs]),
            ("ipdr_records", [r.to_dict() for r in result.ipdr_records]),
            ("url_requests", [u.to_dict() for u in result.url_requests]),
            ("snort_alerts", [a.to_dict() for a in result.snort_alerts]),
        ]

        for name, data in datasets:
            if not data:
                continue
            base = os.path.join(out_dir, f"{prefix}{name}_{ts}")
            if self.config.save_to_json:
                jpath = base + ".json"
                _save_json(data, jpath)
                paths[f"{name}_json"] = jpath
            if self.config.save_to_csv:
                cpath = base + ".csv"
                _save_csv(data, cpath)
                paths[f"{name}_csv"] = cpath

        # Save summary
        summary_path = os.path.join(out_dir, f"{prefix}summary_{ts}.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(result.summary(), f, indent=2)
        logger.info("Saved summary → %s", summary_path)
        paths["summary"] = summary_path

        return paths
