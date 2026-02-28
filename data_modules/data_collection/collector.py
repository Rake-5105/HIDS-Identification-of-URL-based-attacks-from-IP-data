"""
Main Data Collection Orchestrator.
Entry point for the data collection subsystem of the
URL-based Attack Identification project.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .config import CollectionConfig
from .log_ingestion import LogIngestionPipeline
from .models import CollectionResult

logger = logging.getLogger(__name__)


def setup_logging(config: CollectionConfig) -> None:
    """Configure root logger for the module."""
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    if config.log_file:
        os.makedirs(config.output_directory, exist_ok=True)
        handlers.append(logging.FileHandler(
            os.path.join(config.output_directory, config.log_file),
            encoding="utf-8",
        ))
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


# ─────────────────────────────────────────────────────────────────────────────
# DataCollector — public API
# ─────────────────────────────────────────────────────────────────────────────

class DataCollector:
    """
    High-level API for the Data Collection Module.

    Supports:
      - Single file ingestion (HTTP log, IPDR CSV, PCAP)
      - Directory-based batch ingestion
      - Automatic format detection
      - Result persistence (JSON + CSV)
      - Per-IP summary statistics

    Example
    -------
    >>> collector = DataCollector()
    >>> result   = collector.collect(source="/var/log/nginx/")
    >>> collector.print_summary(result)
    >>> collector.save(result, tag="nginx_run1")
    """

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config   = config or CollectionConfig()
        setup_logging(self.config)
        self.pipeline = LogIngestionPipeline(self.config)
        logger.info("DataCollector initialised (output → %s)",
                    self.config.output_directory)

    # ── Core collection ──────────────────────────────────────────────────

    def collect(self, source: Optional[str] = None) -> CollectionResult:
        """
        Collect data from *source*.

        Parameters
        ----------
        source : str or None
            • Path to a single file (log / IPDR CSV / PCAP)
            • Path to a directory  (recursively scanned)
            • None → uses configured log_directory + pcap_directory

        Returns
        -------
        CollectionResult
        """
        start = datetime.now()
        logger.info("=" * 60)
        logger.info("Data collection started  @ %s", start.strftime("%Y-%m-%d %H:%M:%S"))

        if source is not None:
            result = self.pipeline.ingest_path(source)
        else:
            result = self.pipeline.ingest_defaults()

        elapsed = (datetime.now() - start).total_seconds()
        logger.info("Data collection finished @ %s  (%.2fs)",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"), elapsed)
        logger.info("Summary: %s", result.summary())
        logger.info("=" * 60)
        return result

    # ── Save ─────────────────────────────────────────────────────────────

    def save(self, result: CollectionResult,
             tag: str = "") -> Dict[str, str]:
        """Persist result to output_directory. Returns saved file paths."""
        return self.pipeline.save_results(result, tag=tag)

    # ── Convenience ──────────────────────────────────────────────────────

    def collect_and_save(self, source: Optional[str] = None,
                         tag: str = "") -> CollectionResult:
        """Collect data and immediately save results."""
        result = self.collect(source)
        if result.total_records > 0:
            paths = self.save(result, tag=tag)
            logger.info("Saved %d output files.", len(paths))
        return result

    # ── Reporting ─────────────────────────────────────────────────────────

    def print_summary(self, result: CollectionResult) -> None:
        """Print a human-readable summary to stdout."""
        s = result.summary()
        print("\n" + "=" * 55)
        print("  DATA COLLECTION SUMMARY")
        print("=" * 55)
        print(f"  HTTP Log Entries  : {s['http_log_entries']}")
        print(f"  IPDR Records      : {s['ipdr_records']}")
        print(f"  URL Requests      : {s['url_requests']}")
        print(f"  Total Records     : {s['total_records']}")
        print(f"  Source Files      : {len(s['source_files'])}")
        print(f"  Parse Errors      : {s['errors']}")
        if s["source_files"]:
            print("\n  Sources:")
            for f in s["source_files"]:
                print(f"    • {f}")
        if result.errors:
            print("\n  Errors:")
            for e in result.errors:
                print(f"    ✗ {e}")
        print("=" * 55 + "\n")

    def ip_summary(self, result: CollectionResult) -> Dict:
        """Return per-IP aggregated stats from IPDR records."""
        from .ipdr_collector import IPDRCollector
        return IPDRCollector.summarise_by_ip(result.ipdr_records)

    def top_requestors(self, result: CollectionResult, n: int = 10):
        """Return top-N IPs by URL request count."""
        from .pcap_analyzer import PCAPAnalyzer
        return PCAPAnalyzer.top_requestors(result.url_requests, n)

    def top_paths(self, result: CollectionResult, n: int = 20):
        """Return top-N requested URL paths."""
        from .pcap_analyzer import PCAPAnalyzer
        return PCAPAnalyzer.top_paths(result.url_requests, n)