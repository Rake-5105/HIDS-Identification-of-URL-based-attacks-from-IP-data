"""
PCAP Analyzer.
Extracts HTTP/HTTPS request metadata from packet capture files (.pcap/.pcapng).
Uses dpkt (primary) with a fallback stub when dpkt is unavailable.
"""

import logging
import os
import socket
import struct
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .models import URLRequest, HTTPLogEntry, LogSource
from .config import CollectionConfig

logger = logging.getLogger(__name__)

# ── Try importing dpkt ───────────────────────────────────────────────────────
try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False
    logger.warning(
        "dpkt is not installed. PCAP analysis will be limited. "
        "Install with: pip install dpkt"
    )

# ── Try importing scapy as secondary backend ─────────────────────────────────
try:
    from scapy.all import rdpcap, TCP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ip_to_str(addr: bytes) -> str:
    try:
        return socket.inet_ntoa(addr)
    except Exception:
        return str(addr)


def _ts_to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def _parse_http_request(payload: bytes, src_ip: str, dst_ip: str,
                        dst_port: int, ts: datetime,
                        source: LogSource = LogSource.PCAP
                        ) -> Optional[URLRequest]:
    """
    Attempt to parse an HTTP request from raw TCP payload bytes.
    Returns a URLRequest or None if the payload is not a valid HTTP request.
    """
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return None

    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines:
        return None

    # First line: METHOD /path HTTP/x.y
    first = lines[0].strip()
    parts = first.split(" ")
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD",
                      "OPTIONS", "PATCH", "CONNECT", "TRACE"}:
        return None

    raw_path = parts[1]

    # Parse headers
    headers: dict = {}
    for line in lines[1:]:
        if ": " in line:
            k, _, v = line.partition(": ")
            headers[k.lower().strip()] = v.strip()
        if line.strip() == "":
            break  # end of headers

    host       = headers.get("host", dst_ip)
    user_agent = headers.get("user-agent")
    referrer   = headers.get("referer") or headers.get("referrer")

    # Build full URL
    scheme    = "https" if dst_port in (443, 8443) else "http"
    full_url  = f"{scheme}://{host}{raw_path}"
    parsed    = urlparse(full_url)

    return URLRequest(
        source_ip=src_ip,
        timestamp=ts,
        full_url=full_url,
        method=method,
        host=host,
        path=parsed.path,
        query_string=parsed.query,
        fragment=parsed.fragment,
        user_agent=user_agent,
        referrer=referrer,
        source=source,
        raw=first,
    )


# ─────────────────────────────────────────────────────────────────────────────
# dpkt-based backend
# ─────────────────────────────────────────────────────────────────────────────

def _extract_with_dpkt(filepath: str,
                       http_ports: List[int],
                       https_ports: List[int],
                       max_payload_kb: int
                       ) -> Tuple[List[URLRequest], List[HTTPLogEntry]]:
    requests: List[URLRequest]  = []
    entries:  List[HTTPLogEntry] = []
    max_bytes = max_payload_kb * 1024

    try:
        with open(filepath, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip_pkt = eth.data

                if not isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    continue
                tcp = ip_pkt.data

                src_ip  = _ip_to_str(ip_pkt.src)
                dst_ip  = _ip_to_str(ip_pkt.dst)
                dst_port = tcp.dport
                payload  = bytes(tcp.data)

                if not payload or len(payload) > max_bytes:
                    continue
                if dst_port not in http_ports and dst_port not in https_ports:
                    continue

                dt  = _ts_to_datetime(ts)
                req = _parse_http_request(payload, src_ip, dst_ip,
                                          dst_port, dt)
                if req:
                    requests.append(req)

    except Exception as exc:
        logger.error("dpkt parsing error on %s: %s", filepath, exc)

    return requests, entries


# ─────────────────────────────────────────────────────────────────────────────
# Scapy-based fallback backend
# ─────────────────────────────────────────────────────────────────────────────

def _extract_with_scapy(filepath: str,
                        http_ports: List[int],
                        https_ports: List[int],
                        max_payload_kb: int
                        ) -> Tuple[List[URLRequest], List[HTTPLogEntry]]:
    requests: List[URLRequest] = []
    max_bytes = max_payload_kb * 1024

    try:
        packets = rdpcap(filepath)
        for pkt in packets:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            dst_port = pkt[TCP].dport
            if dst_port not in http_ports and dst_port not in https_ports:
                continue

            payload = bytes(pkt[Raw].load)
            if not payload or len(payload) > max_bytes:
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ts     = datetime.fromtimestamp(float(pkt.time))
            req    = _parse_http_request(payload, src_ip, dst_ip, dst_port, ts)
            if req:
                requests.append(req)

    except Exception as exc:
        logger.error("Scapy parsing error on %s: %s", filepath, exc)

    return requests, []


# ─────────────────────────────────────────────────────────────────────────────
# Public PCAP Analyzer class
# ─────────────────────────────────────────────────────────────────────────────

class PCAPAnalyzer:
    """
    Extracts URL requests from PCAP/PCAPNG files.

    Backend priority: dpkt → scapy → stub (no packets extracted).
    """

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config = config or CollectionConfig()

    def analyze_file(self, filepath: str
                     ) -> Tuple[List[URLRequest], List[HTTPLogEntry]]:
        """
        Analyze a single PCAP file.
        Returns (url_requests, http_log_entries).
        """
        if not os.path.isfile(filepath):
            logger.error("PCAP file not found: %s", filepath)
            return [], []

        ext = os.path.splitext(filepath)[1].lower()
        if ext not in self.config.pcap_extensions:
            logger.warning("Unsupported PCAP extension: %s", ext)
            return [], []

        logger.info("Analyzing PCAP: %s", filepath)

        http_ports  = self.config.pcap_http_ports
        https_ports = self.config.pcap_https_ports
        max_kb      = self.config.pcap_max_payload_kb

        if DPKT_AVAILABLE:
            reqs, entries = _extract_with_dpkt(
                filepath, http_ports, https_ports, max_kb)
        elif SCAPY_AVAILABLE:
            logger.info("Using scapy backend (dpkt not available)")
            reqs, entries = _extract_with_scapy(
                filepath, http_ports, https_ports, max_kb)
        else:
            logger.error(
                "No PCAP backend available. "
                "Install dpkt (`pip install dpkt`) or scapy (`pip install scapy`)."
            )
            return [], []

        logger.info("  → %d URL requests extracted from %s",
                    len(reqs), os.path.basename(filepath))
        return reqs, entries

    def analyze_directory(self, directory: str
                          ) -> Tuple[List[URLRequest], List[HTTPLogEntry]]:
        """Analyze all PCAP files in a directory."""
        all_reqs:    List[URLRequest]  = []
        all_entries: List[HTTPLogEntry] = []

        if not os.path.isdir(directory):
            logger.error("Directory not found: %s", directory)
            return all_reqs, all_entries

        for fname in sorted(os.listdir(directory)):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in self.config.pcap_extensions:
                continue
            reqs, entries = self.analyze_file(os.path.join(directory, fname))
            all_reqs.extend(reqs)
            all_entries.extend(entries)

        return all_reqs, all_entries

    # ── Statistics helpers ────────────────────────────────────────────────

    @staticmethod
    def top_requestors(requests: List[URLRequest], n: int = 10
                       ) -> List[Tuple[str, int]]:
        """Return the top-N IPs by request count."""
        from collections import Counter
        counts = Counter(r.source_ip for r in requests)
        return counts.most_common(n)

    @staticmethod
    def top_paths(requests: List[URLRequest], n: int = 20
                  ) -> List[Tuple[str, int]]:
        """Return the top-N requested URL paths."""
        from collections import Counter
        counts = Counter(r.path for r in requests)
        return counts.most_common(n)