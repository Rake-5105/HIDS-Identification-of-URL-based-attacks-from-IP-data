"""
IP Detail Record (IPDR) Collector.
Ingests IPDR data from CSV/TSV files, generates per-IP session summaries,
and correlates with HTTP log data.
"""

import csv
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from .models import IPDRRecord, URLRequest, LogSource
from .config import CollectionConfig

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Column name aliases → canonical names
# ─────────────────────────────────────────────────────────────────────────────

COLUMN_ALIASES: Dict[str, str] = {
    # source IP
    "src_ip": "source_ip", "source": "source_ip", "client_ip": "source_ip",
    "c-ip":   "source_ip", "srcip": "source_ip",
    # destination IP
    "dst_ip": "destination_ip", "dest_ip": "destination_ip",
    "server_ip": "destination_ip", "s-ip": "destination_ip",
    # ports
    "src_port": "source_port",  "sport": "source_port",
    "dst_port": "destination_port", "dport": "destination_port",
    "dest_port": "destination_port",
    # protocol
    "proto": "protocol",
    # timing
    "start":  "start_time", "begin_time": "start_time",
    "end":    "end_time",   "stop_time":  "end_time",
    # bytes
    "sent_bytes": "bytes_sent",  "out_bytes": "bytes_sent",
    "recv_bytes": "bytes_received", "in_bytes": "bytes_received",
    "bytes_in":   "bytes_received", "bytes_out": "bytes_sent",
    # packets
    "sent_pkts": "packets_sent",  "out_pkts": "packets_sent",
    "recv_pkts": "packets_received", "in_pkts": "packets_received",
    # misc
    "session": "session_id", "flow_id": "session_id",
    "fqdn":    "domain",     "hostname": "domain",
    "url_cnt": "url_count",
}


def _normalise_header(col: str) -> str:
    cleaned = col.strip().lower().lstrip("#").strip()
    return COLUMN_ALIASES.get(cleaned, cleaned)


def _safe_int(val: str, default: int = 0) -> int:
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return default


def _parse_ts(val: str) -> Optional[datetime]:
    from .config import TIMESTAMP_FORMATS
    val = str(val).strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# IPDR File Parser
# ─────────────────────────────────────────────────────────────────────────────

class IPDRCollector:
    """
    Parses IPDR data from CSV / TSV files.
    Produces IPDRRecord objects and optionally correlates them with
    a list of URLRequest objects to enrich the records.

    Expected minimum columns (aliases accepted):
        source_ip, destination_ip, source_port, destination_port,
        protocol, start_time
    """

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config = config or CollectionConfig()

    # ── Low-level row → IPDRRecord ────────────────────────────────────────

    def _row_to_record(self, row: Dict[str, str]) -> Optional[IPDRRecord]:
        src_ip = row.get("source_ip", "").strip()
        dst_ip = row.get("destination_ip", "").strip()
        if not src_ip or not dst_ip:
            return None

        start = _parse_ts(row.get("start_time", ""))
        if start is None:
            return None

        end_raw = row.get("end_time", "")
        end = _parse_ts(end_raw) if end_raw else None

        record = IPDRRecord(
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=_safe_int(row.get("source_port", "0")),
            destination_port=_safe_int(row.get("destination_port", "0")),
            protocol=row.get("protocol", "TCP").upper(),
            start_time=start,
            end_time=end,
            bytes_sent=_safe_int(row.get("bytes_sent", "0")),
            bytes_received=_safe_int(row.get("bytes_received", "0")),
            packets_sent=_safe_int(row.get("packets_sent", "0")),
            packets_received=_safe_int(row.get("packets_received", "0")),
            session_id=row.get("session_id") or None,
            domain=row.get("domain") or None,
            url_count=_safe_int(row.get("url_count", "0")),
        )
        return record

    # ── Single file ───────────────────────────────────────────────────────

    def parse_file(self, filepath: str) -> List[IPDRRecord]:
        """Parse a single IPDR CSV/TSV file and return a list of records."""
        records: List[IPDRRecord] = []
        if not os.path.isfile(filepath):
            logger.error("IPDR file not found: %s", filepath)
            return records

        ext       = os.path.splitext(filepath)[1].lower()
        delimiter = "\t" if ext in (".tsv",) else self.config.ipdr_delimiter

        logger.info("Parsing IPDR file: %s", filepath)

        try:
            with open(filepath, newline="",
                      encoding=self.config.encoding,
                      errors="replace") as fh:
                reader = csv.DictReader(fh, delimiter=delimiter)
                if reader.fieldnames is None:
                    logger.warning("No header found in %s", filepath)
                    return records

                # Normalise column names
                reader.fieldnames = [_normalise_header(c)
                                     for c in reader.fieldnames]

                for row in reader:
                    norm_row = {_normalise_header(k): v
                                for k, v in row.items()}
                    record = self._row_to_record(norm_row)
                    if record:
                        records.append(record)

        except Exception as exc:
            logger.error("Error reading IPDR file %s: %s", filepath, exc)

        logger.info("  → %d IPDR records parsed from %s",
                    len(records), os.path.basename(filepath))
        return records

    # ── Directory ─────────────────────────────────────────────────────────

    def parse_directory(self, directory: str) -> List[IPDRRecord]:
        """Parse all CSV/TSV files in a directory."""
        all_records: List[IPDRRecord] = []
        if not os.path.isdir(directory):
            logger.error("Directory not found: %s", directory)
            return all_records

        for fname in sorted(os.listdir(directory)):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".csv", ".tsv", ".txt"):
                continue
            all_records.extend(
                self.parse_file(os.path.join(directory, fname))
            )
        return all_records

    # ── Correlation with HTTP logs ─────────────────────────────────────────

    def correlate_with_urls(
        self,
        records: List[IPDRRecord],
        url_requests: List[URLRequest],
    ) -> List[IPDRRecord]:
        """
        Enrich IPDR records with url_count from matching URL requests.
        Matching is done on source_ip + time window overlap.
        """
        # Index URL requests by source IP
        url_index: Dict[str, List[URLRequest]] = defaultdict(list)
        for req in url_requests:
            url_index[req.source_ip].append(req)

        def _naive(dt: datetime) -> datetime:
            """Strip timezone so all comparisons are offset-naive."""
            return dt.replace(tzinfo=None) if dt.tzinfo else dt

        for record in records:
            matching = url_index.get(record.source_ip, [])
            count = 0
            rec_start = _naive(record.start_time)
            rec_end   = _naive(record.end_time) if record.end_time else None
            for req in matching:
                req_ts = _naive(req.timestamp)
                if rec_end:
                    if rec_start <= req_ts <= rec_end:
                        count += 1
                else:
                    if req_ts >= rec_start:
                        count += 1
            if count > 0:
                record.url_count = count

        return records

    # ── Summary statistics ────────────────────────────────────────────────

    @staticmethod
    def summarise_by_ip(records: List[IPDRRecord]
                        ) -> Dict[str, Dict]:
        """Return per-IP aggregated statistics."""
        summary: Dict[str, Dict] = {}
        for rec in records:
            ip = rec.source_ip
            if ip not in summary:
                summary[ip] = {
                    "session_count":   0,
                    "total_bytes":     0,
                    "total_packets":   0,
                    "total_urls":      0,
                    "unique_dst_ips":  set(),
                    "protocols":       set(),
                    "first_seen":      rec.start_time,
                    "last_seen":       rec.start_time,
                }
            s = summary[ip]
            s["session_count"]  += 1
            s["total_bytes"]    += rec.total_bytes
            s["total_packets"]  += rec.packets_sent + rec.packets_received
            s["total_urls"]     += rec.url_count
            s["unique_dst_ips"].add(rec.destination_ip)
            s["protocols"].add(rec.protocol)
            if rec.start_time < s["first_seen"]:
                s["first_seen"] = rec.start_time
            last = rec.end_time or rec.start_time
            if last > s["last_seen"]:
                s["last_seen"] = last

        # Convert sets to lists for serialisability
        for ip in summary:
            summary[ip]["unique_dst_ips"] = list(summary[ip]["unique_dst_ips"])
            summary[ip]["protocols"]      = list(summary[ip]["protocols"])
            summary[ip]["first_seen"]     = summary[ip]["first_seen"].isoformat()
            summary[ip]["last_seen"]      = summary[ip]["last_seen"].isoformat()

        return summary
