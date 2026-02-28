"""
Configuration settings for the Data Collection Module.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CollectionConfig:
    # ── Log file settings ────────────────────────────────────────────────────
    log_directory:        str       = "logs"
    pcap_directory:       str       = "pcap_files"
    output_directory:     str       = "output"

    # ── Supported file extensions ────────────────────────────────────────────
    log_extensions:       List[str] = field(default_factory=lambda: [
        ".log", ".txt", ".gz", ".bz2", ".zip"
    ])
    pcap_extensions:      List[str] = field(default_factory=lambda: [
        ".pcap", ".pcapng", ".cap"
    ])

    # ── Parser settings ──────────────────────────────────────────────────────
    max_file_size_mb:     int       = 500          # skip files larger than this
    encoding:             str       = "utf-8"
    encoding_fallback:    str       = "latin-1"
    batch_size:           int       = 10_000       # records per processing batch

    # ── PCAP settings ────────────────────────────────────────────────────────
    pcap_http_ports:      List[int] = field(default_factory=lambda: [
        80, 8080, 8000, 8888, 3000, 5000
    ])
    pcap_https_ports:     List[int] = field(default_factory=lambda: [
        443, 8443
    ])
    pcap_max_payload_kb:  int       = 64

    # ── IPDR settings ────────────────────────────────────────────────────────
    ipdr_delimiter:       str       = ","
    ipdr_has_header:      bool      = True

    # ── Snort settings ───────────────────────────────────────────────────────
    snort_directory:      str       = "snort_logs"
    snort_extensions:     List[str] = field(default_factory=lambda: [
        ".log", ".txt", ".alert", ".csv"
    ])

    # ── Output settings ──────────────────────────────────────────────────────
    save_to_json:         bool      = True
    save_to_csv:          bool      = True

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level:            str       = "INFO"
    log_file:             Optional[str] = "data_collection.log"

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        for d in [self.log_directory, self.pcap_directory, self.output_directory]:
            os.makedirs(d, exist_ok=True)


# ── Apache Combined Log Format ───────────────────────────────────────────────
# e.g.: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "-" "Mozilla/4.08"
APACHE_COMBINED_PATTERN = (
    r'(?P<source_ip>\S+)\s+'           # client IP
    r'\S+\s+'                           # ident
    r'\S+\s+'                           # auth user
    r'\[(?P<timestamp>[^\]]+)\]\s+'     # timestamp
    r'"(?P<method>\S+)\s+'             # HTTP method
    r'(?P<url>\S+)\s+'                 # URL
    r'(?P<protocol>[^"]+)"\s+'         # protocol
    r'(?P<status_code>\d{3})\s+'       # status code
    r'(?P<response_size>\S+)'          # response size
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'  # optional
)

# ── Nginx default log format ─────────────────────────────────────────────────
NGINX_PATTERN = (
    r'(?P<source_ip>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<url>\S+)\s+'
    r'(?P<protocol>[^"]+)"\s+'
    r'(?P<status_code>\d{3})\s+'
    r'(?P<response_size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# ── IIS W3C Extended Log Format ──────────────────────────────────────────────
# Fields line defines the columns dynamically
IIS_DATETIME_FMT = "%Y-%m-%d %H:%M:%S"

# ── Timestamp formats tried in order ─────────────────────────────────────────
TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Apache / Nginx
    "%Y-%m-%d %H:%M:%S",      # IIS / generic
    "%Y-%m-%dT%H:%M:%S%z",    # ISO 8601
    "%d/%m/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",         # Syslog
]

# ── Snort log patterns ────────────────────────────────────────────────────────
#
# Fast-alert / unified text output:
#   01/28-22:31:18.123456 [**] [1:1000001:1] Some message [**]
#   [Classification: Web App Attack] [Priority: 1] {TCP} 1.2.3.4:1234 -> 5.6.7.8:80
#
SNORT_FAST_PATTERN = (
    r'(?P<timestamp>\d{2}/\d{2}(?:-\d{2})?[\s\-]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'(?P<msg>.+?)\s+\[\*\*\]'
    r'(?:\s+\[Classification:\s*(?P<classification>[^\]]+)\])?'
    r'(?:\s+\[Priority:\s*(?P<priority>\d+)\])?'
    r'\s+\{(?P<proto>\w+)\}\s+'
    r'(?P<src_ip>[\d\.]+)(?::(?P<src_port>\d+))?\s+->\s+'
    r'(?P<dst_ip>[\d\.]+)(?::(?P<dst_port>\d+))?'
)

# Full-alert supplementary lines (TTL / IpLen / DgmLen etc.)
SNORT_FULL_HDR_PATTERN = (
    r'TTL:(?P<ttl>\d+)\s+TOS:(?P<tos>\S+)\s+ID:\d+\s+'
    r'IpLen:(?P<ip_len>\d+)\s+DgmLen:(?P<dgm_len>\d+)'
)

SNORT_FULL_TCP_PATTERN = (
    r'(?P<tcp_flags>[A-Z *]+)\s+Seq:\s*(?P<tcp_seq>\S+)'
    r'\s+Ack:\s*(?P<tcp_ack>\S+)\s+Win:\s*(?P<tcp_win>\S+)'
)

# CSV header produced by Snort's csv output plugin
SNORT_CSV_FIELDS = [
    "timestamp", "sig_generator", "sig_id", "sig_rev", "msg",
    "proto", "src", "srcport", "dst", "dstport",
    "ethsrc", "ethdst", "ethlen", "tcpflags",
    "tcpseq", "tcpack", "tcplen", "tcpwindow",
    "ttl", "tos", "id", "dgmlen", "iplen",
]

# Snort timestamp formats
SNORT_TIMESTAMP_FORMATS = [
    "%m/%d-%H:%M:%S.%f",      # 01/28-22:31:18.123456
    "%m/%d/%y-%H:%M:%S.%f",   # 01/28/25-22:31:18.123456
    "%Y/%m/%d-%H:%M:%S.%f",
    "%m/%d-%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
]
