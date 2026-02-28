"""
HTTP Access Log Parser.
Parses Apache Combined/Common, Nginx, and IIS W3C Extended log formats.
Also handles gzip/bzip2 compressed logs.
"""

import re
import gzip
import bz2
import zipfile
import logging
import os
from datetime import datetime
from typing import Iterator, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from .models import HTTPLogEntry, URLRequest, LogSource
from .config import (
    CollectionConfig,
    APACHE_COMBINED_PATTERN,
    NGINX_PATTERN,
    TIMESTAMP_FORMATS,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp helper
# ─────────────────────────────────────────────────────────────────────────────

def _parse_timestamp(raw: str) -> Optional[datetime]:
    """Try multiple timestamp formats until one succeeds."""
    raw = raw.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    logger.debug("Could not parse timestamp: %s", raw)
    return None


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


# ─────────────────────────────────────────────────────────────────────────────
# URL decomposition
# ─────────────────────────────────────────────────────────────────────────────

def decompose_url(raw_url: str, source_ip: str, timestamp: datetime,
                  method: str, status_code: int, user_agent: Optional[str],
                  referrer: Optional[str], source: LogSource) -> URLRequest:
    """Break a raw URL string into a URLRequest with host/path/query parts."""
    parsed = urlparse(raw_url)
    host   = parsed.netloc or ""
    path   = parsed.path   or raw_url
    return URLRequest(
        source_ip=source_ip,
        timestamp=timestamp,
        full_url=raw_url,
        method=method,
        host=host,
        path=path,
        query_string=parsed.query,
        fragment=parsed.fragment,
        status_code=status_code,
        user_agent=user_agent,
        referrer=referrer,
        source=source,
    )


# ─────────────────────────────────────────────────────────────────────────────
# File opening helpers (supports .gz, .bz2, .zip)
# ─────────────────────────────────────────────────────────────────────────────

def _open_log_file(filepath: str, encoding: str = "utf-8", fallback: str = "latin-1"):
    """Open a plain, gzip, bzip2, or zip log file and yield text lines."""
    ext = os.path.splitext(filepath)[1].lower()
    try:
        if ext == ".gz":
            with gzip.open(filepath, "rt", encoding=encoding, errors="replace") as f:
                yield from f
        elif ext in (".bz2", ".bz"):
            with bz2.open(filepath, "rt", encoding=encoding, errors="replace") as f:
                yield from f
        elif ext == ".zip":
            with zipfile.ZipFile(filepath) as zf:
                for name in zf.namelist():
                    with zf.open(name) as entry:
                        for line in entry:
                            yield line.decode(encoding, errors="replace")
        else:
            try:
                with open(filepath, "r", encoding=encoding, errors="replace") as f:
                    yield from f
            except UnicodeDecodeError:
                with open(filepath, "r", encoding=fallback, errors="replace") as f:
                    yield from f
    except Exception as exc:
        logger.error("Cannot open %s: %s", filepath, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Apache / Nginx parser
# ─────────────────────────────────────────────────────────────────────────────

class ApacheNginxParser:
    """
    Parses Apache Combined / Nginx default access logs.
    Auto-detects the format on the first successfully matched line.
    """

    PATTERNS = {
        LogSource.APACHE: re.compile(APACHE_COMBINED_PATTERN),
        LogSource.NGINX:  re.compile(NGINX_PATTERN),
    }

    def __init__(self, config: CollectionConfig):
        self.config   = config
        self._pattern = None
        self._source  = LogSource.CUSTOM

    def _detect_format(self, line: str) -> Optional[Tuple[re.Pattern, LogSource]]:
        for src, pat in self.PATTERNS.items():
            if pat.match(line.strip()):
                return pat, src
        return None

    def _parse_line(self, line: str) -> Optional[HTTPLogEntry]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        if self._pattern is None:
            result = self._detect_format(line)
            if result is None:
                return None
            self._pattern, self._source = result
            logger.info("Detected log format: %s", self._source.value)

        m = self._pattern.match(line)
        if not m:
            return None

        g = m.groupdict()
        ts = _parse_timestamp(g.get("timestamp", ""))
        if ts is None:
            return None

        size_raw = g.get("response_size", "0")
        return HTTPLogEntry(
            source_ip=g["source_ip"],
            timestamp=ts,
            method=g.get("method", "GET"),
            url=g.get("url", "/"),
            protocol=g.get("protocol", "HTTP/1.1"),
            status_code=_safe_int(g.get("status_code", "0")),
            response_size=_safe_int(size_raw),
            referrer=g.get("referrer") or None,
            user_agent=g.get("user_agent") or None,
            source=self._source,
            raw_line=line,
        )

    def parse_file(self, filepath: str) -> Tuple[List[HTTPLogEntry], List[URLRequest]]:
        """Parse a complete log file, returning log entries and URL requests."""
        entries:  List[HTTPLogEntry] = []
        requests: List[URLRequest]  = []

        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if file_size_mb > self.config.max_file_size_mb:
            logger.warning("Skipping large file (%0.1f MB): %s", file_size_mb, filepath)
            return entries, requests

        logger.info("Parsing log file: %s", filepath)
        for line in _open_log_file(filepath, self.config.encoding,
                                   self.config.encoding_fallback):
            entry = self._parse_line(line)
            if entry:
                entries.append(entry)
                requests.append(
                    decompose_url(
                        raw_url=entry.url,
                        source_ip=entry.source_ip,
                        timestamp=entry.timestamp,
                        method=entry.method,
                        status_code=entry.status_code,
                        user_agent=entry.user_agent,
                        referrer=entry.referrer,
                        source=entry.source,
                    )
                )

        logger.info("  → %d entries parsed from %s", len(entries), os.path.basename(filepath))
        return entries, requests


# ─────────────────────────────────────────────────────────────────────────────
# IIS W3C Extended Log Parser
# ─────────────────────────────────────────────────────────────────────────────

class IISLogParser:
    """
    Parses IIS W3C Extended log format.
    Reads the #Fields directive to determine column order dynamically.
    """

    # Maps IIS field names → our model attribute names
    FIELD_MAP = {
        "c-ip":         "source_ip",
        "cs-uri-stem":  "uri_stem",
        "cs-uri-query": "uri_query",
        "cs-method":    "method",
        "sc-status":    "status_code",
        "sc-bytes":     "response_size",
        "cs(User-Agent)": "user_agent",
        "cs(Referer)":    "referrer",
        "s-ip":         "destination_ip",
        "s-port":       "destination_port",
        "time-taken":   "duration_ms",
        "date":         "date",
        "time":         "time",
    }

    def __init__(self, config: CollectionConfig):
        self.config  = config
        self._fields: List[str] = []

    def _build_entry(self, parts: List[str]) -> Optional[HTTPLogEntry]:
        if len(parts) != len(self._fields):
            return None
        row = dict(zip(self._fields, parts))

        # Compose timestamp from date + time columns
        date_str = row.get("date", "")
        time_str = row.get("time", "")
        ts = _parse_timestamp(f"{date_str} {time_str}") if date_str else None
        if ts is None:
            return None

        uri_stem  = row.get("uri_stem", "/")
        uri_query = row.get("uri_query", "")
        full_url  = f"{uri_stem}?{uri_query}" if uri_query and uri_query != "-" else uri_stem

        return HTTPLogEntry(
            source_ip=row.get("source_ip", "-"),
            timestamp=ts,
            method=row.get("method", "GET"),
            url=full_url,
            protocol="HTTP",
            status_code=_safe_int(row.get("status_code", "0")),
            response_size=_safe_int(row.get("response_size", "0")),
            referrer=row.get("referrer") or None,
            user_agent=row.get("user_agent") or None,
            destination_ip=row.get("destination_ip") or None,
            destination_port=_safe_int(row.get("destination_port", "0")) or None,
            duration_ms=float(row["duration_ms"]) if row.get("duration_ms", "-") != "-" else None,
            source=LogSource.IIS,
        )

    def parse_file(self, filepath: str) -> Tuple[List[HTTPLogEntry], List[URLRequest]]:
        entries:  List[HTTPLogEntry] = []
        requests: List[URLRequest]  = []

        logger.info("Parsing IIS log file: %s", filepath)
        for line in _open_log_file(filepath, self.config.encoding,
                                   self.config.encoding_fallback):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#Fields:"):
                raw_fields = line.replace("#Fields:", "").strip().split()
                self._fields = [self.FIELD_MAP.get(f, f) for f in raw_fields]
                continue
            if line.startswith("#"):
                continue

            entry = self._build_entry(line.split())
            if entry:
                entries.append(entry)
                requests.append(
                    decompose_url(
                        raw_url=entry.url,
                        source_ip=entry.source_ip,
                        timestamp=entry.timestamp,
                        method=entry.method,
                        status_code=entry.status_code,
                        user_agent=entry.user_agent,
                        referrer=entry.referrer,
                        source=LogSource.IIS,
                    )
                )

        logger.info("  → %d IIS entries parsed from %s", len(entries), os.path.basename(filepath))
        return entries, requests


# ─────────────────────────────────────────────────────────────────────────────
# Auto-detecting parser facade
# ─────────────────────────────────────────────────────────────────────────────

class HTTPLogParser:
    """
    Auto-detects the log format of a file (Apache/Nginx/IIS)
    and delegates parsing to the appropriate sub-parser.
    """

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config = config or CollectionConfig()
        self._apache_nginx = ApacheNginxParser(self.config)
        self._iis          = IISLogParser(self.config)

    def _is_iis(self, filepath: str) -> bool:
        """Peek at the first few lines to determine if it's IIS W3C format."""
        for line in _open_log_file(filepath, self.config.encoding,
                                   self.config.encoding_fallback):
            line = line.strip()
            if line.startswith("#Fields:"):
                return True
            if line and not line.startswith("#"):
                break
        return False

    def parse_file(self, filepath: str) -> Tuple[List[HTTPLogEntry], List[URLRequest]]:
        """Parse a log file, auto-detecting its format."""
        if not os.path.isfile(filepath):
            logger.error("File not found: %s", filepath)
            return [], []

        if self._is_iis(filepath):
            return self._iis.parse_file(filepath)
        else:
            # Reset pattern detection for each new file
            self._apache_nginx._pattern = None
            return self._apache_nginx.parse_file(filepath)

    def parse_directory(self, directory: str
                        ) -> Tuple[List[HTTPLogEntry], List[URLRequest]]:
        """Parse all supported log files in a directory."""
        all_entries:  List[HTTPLogEntry] = []
        all_requests: List[URLRequest]  = []

        if not os.path.isdir(directory):
            logger.error("Directory not found: %s", directory)
            return all_entries, all_requests

        for fname in sorted(os.listdir(directory)):
            fpath = os.path.join(directory, fname)
            ext   = os.path.splitext(fname)[1].lower()
            if ext not in self.config.log_extensions:
                continue
            entries, requests = self.parse_file(fpath)
            all_entries.extend(entries)
            all_requests.extend(requests)

        return all_entries, all_requests
