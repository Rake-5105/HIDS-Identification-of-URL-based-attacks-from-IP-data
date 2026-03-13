"""
URL Parsing Module — Pipeline
================================
High-level orchestrator for Module 2.
Accepts a CollectionResult (from Module 1) or a plain list of URLRequest
objects and returns a fully-populated ParseResult.

Usage
-----
    from data_modules.url_parsing import URLParsingPipeline

    pipeline = URLParsingPipeline()
    result   = pipeline.run(collection_result)       # from Module 1
    pipeline.print_summary(result)
    pipeline.save(result, output_dir="output/", tag="run01")
"""

import csv
import json
import logging
import os
from datetime import datetime
from typing import List, Optional, Union

from .models      import ParseResult, ParsedURL
from .parser      import URLParser
from .normalizer  import URLNormalizer

logger = logging.getLogger(__name__)


class URLParsingPipeline:
    """
    Orchestrates the full URL parsing workflow.

    Steps
    -----
    1. Accept URLRequest records (or a CollectionResult) from Module 1.
    2. Parse each raw URL into a ParsedURL (URLParser).
    3. Normalise each ParsedURL (URLNormalizer).
    4. Return ParseResult.

    Parameters
    ----------
    normalize       : Enable/disable the normalisation pass (default True).
    strip_params    : Query-param keys to strip during normalisation.
                      Pass None to use defaults, empty set to disable.
    """

    def __init__(
        self,
        normalize:    bool             = True,
        strip_params: Optional[set]    = None,
    ):
        self.parser     = URLParser()
        self.normalizer = URLNormalizer(strip_params=strip_params) if normalize else None

    # ── Core API ──────────────────────────────────────────────────────────

    def run(
        self,
        source,                        # CollectionResult or List[URLRequest]
        tag:  str = "",
    ) -> ParseResult:
        """
        Parse and normalise URL records.

        Parameters
        ----------
        source : Either a Module-1 CollectionResult or a plain list of
                 URLRequest-like objects.
        tag    : Optional label stored in ParseResult.source_tag.
        """
        logger.info("=" * 60)
        logger.info("URL Parsing Module started  @ %s",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # ── Extract URL records from whatever was passed in ────────────────
        records = self._extract_records(source)
        logger.info("  Input records : %d", len(records))

        # ── Parse ──────────────────────────────────────────────────────────
        parsed_urls, skipped, errors = self.parser.parse_many(records)

        # ── Normalise ──────────────────────────────────────────────────────
        if self.normalizer and parsed_urls:
            parsed_urls = self.normalizer.normalize_many(parsed_urls)

        result = ParseResult(
            parsed_urls = parsed_urls,
            skipped     = skipped,
            errors      = errors,
            source_tag  = tag,
        )

        logger.info("URL Parsing Module finished @ %s  — %d parsed, %d skipped",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    result.total, result.skipped)
        logger.info("=" * 60)
        return result

    # ── Persistence ───────────────────────────────────────────────────────

    def save(
        self,
        result:     ParseResult,
        output_dir: str  = "output",
        tag:        str  = "",
    ) -> None:
        """Save ParseResult to JSON + CSV files."""
        os.makedirs(output_dir, exist_ok=True)
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        label = f"{tag}_" if tag else ""

        json_path = os.path.join(output_dir, f"{label}parsed_urls_{ts}.json")
        csv_path  = os.path.join(output_dir, f"{label}parsed_urls_{ts}.csv")

        # JSON
        data = [p.to_dict() for p in result.parsed_urls]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info("Saved JSON → %s  (%d records)", json_path, len(data))

        # CSV
        if data:
            # Flatten query_params list to a semicolon-separated string
            flat = []
            for row in data:
                r = dict(row)
                r["path_segments"]  = ";".join(r.get("path_segments", []))
                r["query_params"]   = ";".join(
                    f"{p['key']}={p['value']}" for p in r.get("query_params", [])
                )
                flat.append(r)
            fieldnames = list(flat[0].keys())
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flat)
            logger.info("Saved CSV  → %s  (%d records)", csv_path, len(flat))

    # ── Reporting ─────────────────────────────────────────────────────────

    def print_summary(self, result: ParseResult) -> None:
        """Print a human-readable summary to stdout."""
        s = result.summary()
        print("\n" + "=" * 55)
        print("  URL PARSING MODULE — SUMMARY")
        print("=" * 55)
        print(f"  Total parsed   : {s['total_parsed']}")
        print(f"  Skipped        : {s['skipped']}")
        print(f"  Errors         : {s['errors']}")
        if s["methods"]:
            print("  HTTP Methods   :")
            for m, c in sorted(s["methods"].items(), key=lambda x: -x[1]):
                print(f"    {m:<10} {c}")
        if s["schemes"]:
            print("  Schemes        :")
            for sc, c in sorted(s["schemes"].items(), key=lambda x: -x[1]):
                print(f"    {sc:<10} {c}")
        if s["file_extensions"]:
            print("  File extensions (top 5):")
            for ext, c in sorted(s["file_extensions"].items(),
                                  key=lambda x: -x[1])[:5]:
                print(f"    .{ext:<9} {c}")
        print("=" * 55 + "\n")

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_records(source) -> list:
        """
        Accept either a Module-1 CollectionResult or a plain list,
        and return a flat list of URLRequest-like objects.
        """
        # CollectionResult has a .url_requests attribute
        if hasattr(source, "url_requests"):
            return list(source.url_requests)
        # Plain list
        if isinstance(source, list):
            return source
        raise TypeError(
            f"URLParsingPipeline.run() expects a CollectionResult or list, "
            f"got {type(source).__name__}"
        )
