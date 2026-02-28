"""
Snort IDS Alert Collector.

Parses Snort intrusion-detection alerts from three common output formats:
  1. Fast-alert  (snort -A fast / output alert_fast)
  2. Full-alert  (snort -A full / output alert_full)   — multi-line blocks
  3. CSV output  (output alert_csv)

All three formats are auto-detected by content sniffing.

Typical fast-alert line
-----------------------
01/28-22:31:18.123456 [**] [1:1000001:1] ET SCAN Nmap Scripting Engine [**]
[Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.100:54321 -> 10.0.0.1:80

Typical CSV line (after optional header)
-----------------------------------------
01/28-22:31:18.123456,1,1000001,1,"ET SCAN Nmap...",TCP,192.168.1.100,54321,10.0.0.1,80,...
"""

import csv
import io
import logging
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .models import SnortAlert, LogSource
from .config import (
    CollectionConfig,
    SNORT_FAST_PATTERN,
    SNORT_FULL_HDR_PATTERN,
    SNORT_FULL_TCP_PATTERN,
    SNORT_CSV_FIELDS,
    SNORT_TIMESTAMP_FORMATS,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Compiled regexes
# ─────────────────────────────────────────────────────────────────────────────

_RE_FAST    = re.compile(SNORT_FAST_PATTERN,     re.IGNORECASE)
_RE_FULL_H  = re.compile(SNORT_FULL_HDR_PATTERN, re.IGNORECASE)
_RE_FULL_T  = re.compile(SNORT_FULL_TCP_PATTERN, re.IGNORECASE)

# Detect the [**] alert-block header present in both fast and full formats
_RE_ALERT_HDR = re.compile(r'\[\*\*\].*\[\*\*\]')


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_snort_ts(raw: str, year: int = datetime.now().year) -> Optional[datetime]:
    """
    Parse a Snort timestamp string.
    Snort omits the year in fast/full mode; we inject the current year.
    """
    raw = raw.strip()
    # Inject year when the format is MM/DD-HH:MM:SS...
    yearless = re.match(r'^(\d{2}/\d{2})-', raw)
    if yearless:
        raw = f"{raw[:5]}/{year}-{raw[6:]}"
        fmt_list = [
            "%m/%d/%Y-%H:%M:%S.%f",
            "%m/%d/%Y-%H:%M:%S",
        ]
    else:
        fmt_list = SNORT_TIMESTAMP_FORMATS

    for fmt in fmt_list:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    logger.debug("Could not parse Snort timestamp: %r", raw)
    return None


def _safe_int(v: Optional[str], default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


# ─────────────────────────────────────────────────────────────────────────────
# Format sniffers
# ─────────────────────────────────────────────────────────────────────────────

def _sniff_format(first_lines: List[str]) -> str:
    """
    Return 'fast', 'full', or 'csv' by examining the first non-empty lines.
    """
    for line in first_lines:
        line = line.strip()
        if not line:
            continue
        if _RE_ALERT_HDR.search(line):
            # Distinguish full (multi-line) vs fast (single-line):
            # full blocks end with the [**] header on one line and the
            # classification / addr on subsequent lines, whereas fast
            # already has {PROTO} addr on the SAME line.
            if re.search(r'\{[A-Z0-9]+\}', line):
                return "fast"
            return "full"
        # CSV: first real line should be all-comma-separated fields/numbers
        if re.match(r'[\d/:\\.\-]+,\d+,\d+,\d+,', line):
            return "csv"
        if line.lower().startswith("timestamp,") or "sig_id" in line.lower():
            return "csv"
    return "fast"  # sane default


# ─────────────────────────────────────────────────────────────────────────────
# Per-format parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_fast_line(line: str, year: int) -> Optional[SnortAlert]:
    """Parse a single Snort fast-alert line."""
    m = _RE_FAST.search(line)
    if not m:
        return None
    ts = _parse_snort_ts(m.group("timestamp"), year)
    if ts is None:
        return None
    return SnortAlert(
        timestamp      = ts,
        src_ip         = m.group("src_ip"),
        dst_ip         = m.group("dst_ip"),
        src_port       = _safe_int(m.group("src_port"), 0) or None,
        dst_port       = _safe_int(m.group("dst_port"), 0) or None,
        protocol       = (m.group("proto") or "TCP").upper(),
        generator_id   = _safe_int(m.group("gid"), 1),
        signature_id   = _safe_int(m.group("sid"), 0),
        signature_rev  = _safe_int(m.group("rev"), 0),
        message        = m.group("msg").strip(),
        classification = (m.group("classification") or "").strip() or None,
        priority       = _safe_int(m.group("priority"), 0) or None,
        raw            = line.rstrip(),
    )


def _parse_full_blocks(text: str, year: int) -> List[SnortAlert]:
    """
    Parse Snort full-alert format.

    A full-alert block looks like:
        [**] [gid:sid:rev] message [**]
        [Classification: ...] [Priority: N]
        MM/DD-HH:MM:SS.ffffff SRC_IP:SRC_PORT -> DST_IP:DST_PORT
        Length: NN  TTL: NN  TOS:0xN  ID:NN  IpLen:NN  DgmLen:NN ...
        ***A***S  Seq: 0x...  Ack: 0x...  Win: 0x...  TcpLen: NN
        ...
        (blank line ends the block)
    """
    alerts: List[SnortAlert] = []
    # Split into blocks separated by blank lines
    blocks = re.split(r'\n{2,}', text.strip())

    _re_hdr   = re.compile(
        r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
        r'(?P<msg>.+?)\s+\[\*\*\]', re.IGNORECASE)
    _re_class = re.compile(
        r'\[Classification:\s*(?P<cls>[^\]]+)\]'
        r'(?:\s+\[Priority:\s*(?P<pri>\d+)\])?', re.IGNORECASE)
    _re_addr  = re.compile(
        r'(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
        r'(?P<src>[\d\.]+)(?::(?P<sp>\d+))?\s*->\s*'
        r'(?P<dst>[\d\.]+)(?::(?P<dp>\d+))?', re.IGNORECASE)
    _re_proto = re.compile(r'\{(?P<proto>[A-Z0-9]+)\}', re.IGNORECASE)

    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue

        hdr_m = class_m = addr_m = proto_m = hdr_m2 = None
        hdr_line = ttl_line = tcp_line = ""
        for ln in lines:
            if not hdr_m:
                hdr_m = _re_hdr.search(ln)
            if not class_m:
                class_m = _re_class.search(ln)
            if not addr_m:
                addr_m = _re_addr.search(ln)
            if not proto_m:
                proto_m = _re_proto.search(ln)
            if "TTL:" in ln:
                ttl_line = ln
            if "Seq:" in ln or "TcpLen:" in ln:
                tcp_line = ln

        if not hdr_m or not addr_m:
            continue

        ts = _parse_snort_ts(addr_m.group("ts"), year)
        if ts is None:
            continue

        # Packet-level extras
        ttl_vals = _RE_FULL_H.search(ttl_line) if ttl_line else None
        tcp_vals = _RE_FULL_T.search(tcp_line) if tcp_line else None

        alerts.append(SnortAlert(
            timestamp      = ts,
            src_ip         = addr_m.group("src"),
            dst_ip         = addr_m.group("dst"),
            src_port       = _safe_int(addr_m.group("sp"), 0) or None,
            dst_port       = _safe_int(addr_m.group("dp"), 0) or None,
            protocol       = (proto_m.group("proto") if proto_m else "TCP").upper(),
            generator_id   = _safe_int(hdr_m.group("gid"), 1),
            signature_id   = _safe_int(hdr_m.group("sid"), 0),
            signature_rev  = _safe_int(hdr_m.group("rev"), 0),
            message        = hdr_m.group("msg").strip(),
            classification = class_m.group("cls").strip() if class_m else None,
            priority       = (_safe_int(class_m.group("pri"), 0) or None)
                             if class_m and class_m.group("pri") else None,
            ttl            = _safe_int(ttl_vals.group("ttl")) if ttl_vals else None,
            ip_len         = _safe_int(ttl_vals.group("ip_len")) if ttl_vals else None,
            dgm_len        = _safe_int(ttl_vals.group("dgm_len")) if ttl_vals else None,
            tos            = ttl_vals.group("tos") if ttl_vals else None,
            tcp_flags      = tcp_vals.group("tcp_flags").strip() if tcp_vals else None,
            tcp_seq        = tcp_vals.group("tcp_seq") if tcp_vals else None,
            tcp_ack        = tcp_vals.group("tcp_ack") if tcp_vals else None,
            tcp_win        = tcp_vals.group("tcp_win") if tcp_vals else None,
            raw            = block.strip(),
        ))

    return alerts


def _parse_csv_content(text: str, year: int) -> List[SnortAlert]:
    """
    Parse Snort CSV alert output.

    Snort can write a header line (if output alert_csv: file default) or
    the user may have pre-pended one.  We auto-detect both cases.
    """
    alerts: List[SnortAlert] = []
    reader = csv.reader(io.StringIO(text))
    fieldnames: Optional[List[str]] = None

    for row in reader:
        if not row or not row[0].strip():
            continue

        # Detect header row
        first = row[0].strip().lower()
        if first in ("timestamp", "date") or first.startswith("msg"):
            fieldnames = [f.strip().lower() for f in row]
            continue

        # If no header encountered yet, use default SNORT_CSV_FIELDS order
        names = fieldnames or SNORT_CSV_FIELDS

        rec: Dict[str, str] = {}
        for i, val in enumerate(row):
            if i < len(names):
                rec[names[i]] = val.strip()

        ts_raw = rec.get("timestamp", "")
        ts     = _parse_snort_ts(ts_raw, year)
        if ts is None:
            continue

        src = rec.get("src", "") or rec.get("source_ip", "")
        dst = rec.get("dst", "") or rec.get("destination_ip", "")
        if not src or not dst:
            continue

        alerts.append(SnortAlert(
            timestamp     = ts,
            src_ip        = src,
            dst_ip        = dst,
            src_port      = _safe_int(rec.get("srcport", ""), 0) or None,
            dst_port      = _safe_int(rec.get("dstport", ""), 0) or None,
            protocol      = (rec.get("proto", "TCP") or "TCP").upper(),
            generator_id  = _safe_int(rec.get("sig_generator", "1"), 1),
            signature_id  = _safe_int(rec.get("sig_id", "0"), 0),
            signature_rev = _safe_int(rec.get("sig_rev", "0"), 0),
            message       = rec.get("msg", "").strip('"'),
            ttl           = _safe_int(rec.get("ttl", ""), 0) or None,
            ip_len        = _safe_int(rec.get("iplen", ""), 0) or None,
            dgm_len       = _safe_int(rec.get("dgmlen", ""), 0) or None,
            tos           = rec.get("tos") or None,
            tcp_flags     = rec.get("tcpflags") or None,
            tcp_seq       = rec.get("tcpseq") or None,
            tcp_ack       = rec.get("tcpack") or None,
            tcp_win       = rec.get("tcpwindow") or None,
            raw           = ",".join(row),
        ))

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# SnortCollector — public API
# ─────────────────────────────────────────────────────────────────────────────

class SnortCollector:
    """
    Parses Snort IDS alerts from text files.

    Supported formats (auto-detected):
      * fast-alert  — one alert per line
      * full-alert  — multi-line blocks separated by blank lines
      * CSV         — comma-separated, optional header row

    Example
    -------
    >>> sc = SnortCollector()
    >>> alerts = sc.parse_file("/var/log/snort/alert")
    >>> for a in alerts:
    ...     print(a.timestamp, a.src_ip, "->", a.dst_ip, a.message)
    """

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config = config or CollectionConfig()

    # ── File-level entry point ────────────────────────────────────────────

    def parse_file(self, filepath: str) -> List[SnortAlert]:
        """
        Parse a Snort alert file and return a list of SnortAlert objects.
        The format (fast / full / CSV) is auto-detected from the file content.
        """
        if not os.path.isfile(filepath):
            logger.error("Snort alert file not found: %s", filepath)
            return []

        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > self.config.max_file_size_mb:
            logger.warning("Skipping %s: file too large (%.1f MB)", filepath, size_mb)
            return []

        try:
            text = self._read_file(filepath)
        except Exception as exc:
            logger.error("Cannot read %s: %s", filepath, exc)
            return []

        year = datetime.now().year
        fmt  = _sniff_format(text.splitlines()[:30])
        logger.info("Parsing Snort file [%s format]: %s", fmt, filepath)

        if fmt == "csv":
            alerts = _parse_csv_content(text, year)
        elif fmt == "full":
            alerts = _parse_full_blocks(text, year)
        else:
            alerts = self._parse_fast_text(text, year)

        logger.info("  → %d Snort alerts parsed from %s", len(alerts), filepath)
        return alerts

    # ── Directory-level entry point ──────────────────────────────────────

    def parse_directory(self, directory: str) -> List[SnortAlert]:
        """
        Recursively scan *directory* for Snort alert files and parse them all.
        Files are matched by the extensions in config.snort_extensions.
        """
        if not os.path.isdir(directory):
            logger.error("Snort directory not found: %s", directory)
            return []

        alerts: List[SnortAlert] = []
        exts = set(self.config.snort_extensions)

        for root, _, files in os.walk(directory):
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in exts and fname != "alert":
                    continue
                fpath = os.path.join(root, fname)
                alerts.extend(self.parse_file(fpath))

        logger.info("Total Snort alerts collected from %s: %d", directory, len(alerts))
        return alerts

    # ── Demo / synthetic data ────────────────────────────────────────────

    @staticmethod
    def generate_demo_alerts(n: int = 20) -> List[SnortAlert]:
        """
        Generate *n* synthetic Snort alerts for testing when no real alert
        file is available.
        """
        import random
        from datetime import timedelta

        categories = [
            (1001001, "ET SCAN Nmap OS Detection Probe",
             "Attempted Information Leak", 3),
            (1001002, "ET SCAN Potential SSH Scan",
             "Attempted Information Leak", 2),
            (1001003, "ET WEB_SERVER SQL Injection Attempt",
             "Web Application Attack", 1),
            (1001004, "ET MALWARE CnC Beacon Detected",
             "A Network Trojan was Detected", 1),
            (1001005, "ET POLICY Cleartext Password over HTTP",
             "Policy Violation", 2),
            (1001006, "ET DOS Possible NTP DDoS",
             "Attempted Denial of Service", 2),
            (1001007, "ET EXPLOIT Apache Struts RCE",
             "Attempted Administrator Privilege Gain", 1),
        ]
        src_ips  = ["192.168.1.100", "10.0.0.55", "172.16.0.8",
                    "203.0.113.42", "198.51.100.7"]
        dst_ips  = ["10.10.10.1", "10.10.10.2", "8.8.8.8",
                    "192.168.1.1", "172.16.0.1"]
        protos   = ["TCP", "UDP", "ICMP", "TCP", "TCP"]
        base_ts  = datetime(2026, 2, 28, 0, 0, 0)

        alerts = []
        for i in range(n):
            sid, msg, cls, pri = random.choice(categories)
            alerts.append(SnortAlert(
                timestamp      = base_ts + timedelta(seconds=i * 47 + random.randint(0, 46)),
                src_ip         = random.choice(src_ips),
                dst_ip         = random.choice(dst_ips),
                src_port       = random.randint(1024, 65535),
                dst_port       = random.choice([80, 443, 22, 21, 3306, 8080]),
                protocol       = random.choice(protos),
                generator_id   = 1,
                signature_id   = sid,
                signature_rev  = 1,
                message        = msg,
                classification = cls,
                priority       = pri,
            ))
        return alerts

    # ── Internal helpers ─────────────────────────────────────────────────

    def _read_file(self, filepath: str) -> str:
        for enc in (self.config.encoding, self.config.encoding_fallback, "ascii"):
            try:
                with open(filepath, "r", encoding=enc, errors="replace") as f:
                    return f.read()
            except (UnicodeDecodeError, LookupError):
                continue
        with open(filepath, "r", errors="replace") as f:
            return f.read()

    @staticmethod
    def _parse_fast_text(text: str, year: int) -> List[SnortAlert]:
        alerts = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not _RE_ALERT_HDR.search(line):
                continue
            alert = _parse_fast_line(line, year)
            if alert:
                alerts.append(alert)
        return alerts

    # ── Aggregation helpers ───────────────────────────────────────────────

    @staticmethod
    def top_attackers(alerts: List[SnortAlert], n: int = 10) -> List[Tuple[str, int]]:
        """Return top-N source IPs by alert count."""
        from collections import Counter
        counts = Counter(a.src_ip for a in alerts)
        return counts.most_common(n)

    @staticmethod
    def top_signatures(alerts: List[SnortAlert], n: int = 10) -> List[Tuple[str, int]]:
        """Return top-N signatures by alert count."""
        from collections import Counter
        counts = Counter(f"{a.signature_id} – {a.message}" for a in alerts)
        return counts.most_common(n)

    @staticmethod
    def by_priority(alerts: List[SnortAlert]) -> Dict[int, List[SnortAlert]]:
        """Group alerts by priority level."""
        from collections import defaultdict
        groups: Dict[int, List[SnortAlert]] = defaultdict(list)
        for a in alerts:
            groups[a.priority or 0].append(a)
        return dict(groups)

    @staticmethod
    def summarise(alerts: List[SnortAlert]) -> dict:
        """Return a concise summary dict for the alert collection."""
        if not alerts:
            return {"total": 0}
        from collections import Counter
        return {
            "total":          len(alerts),
            "unique_sources": len({a.src_ip for a in alerts}),
            "unique_dests":   len({a.dst_ip for a in alerts}),
            "unique_sigs":    len({a.signature_id for a in alerts}),
            "by_priority":    dict(Counter(
                                str(a.priority or "unknown") for a in alerts)),
            "by_protocol":    dict(Counter(a.protocol for a in alerts)),
            "top_attackers":  SnortCollector.top_attackers(alerts, 5),
            "top_signatures": SnortCollector.top_signatures(alerts, 5),
        }
