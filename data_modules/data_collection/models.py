"""
Data models for the URL-based Attack Identification System.
Defines schemas for HTTP access logs, IPDR records, and URL requests.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class Protocol(Enum):
    HTTP  = "HTTP"
    HTTPS = "HTTPS"
    FTP   = "FTP"
    OTHER = "OTHER"


class LogSource(Enum):
    APACHE   = "apache"
    NGINX    = "nginx"
    IIS      = "iis"
    PCAP     = "pcap"
    IPDR     = "ipdr"
    SNORT    = "snort"
    CUSTOM   = "custom"


@dataclass
class HTTPLogEntry:
    """Represents a single HTTP access log record."""
    source_ip:        str
    timestamp:        datetime
    method:           str
    url:              str
    protocol:         str
    status_code:      int
    response_size:    int
    referrer:         Optional[str]   = None
    user_agent:       Optional[str]   = None
    destination_ip:   Optional[str]   = None
    destination_port: Optional[int]   = None
    duration_ms:      Optional[float] = None
    source:           LogSource       = LogSource.CUSTOM
    raw_line:         Optional[str]   = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip":        self.source_ip,
            "timestamp":        self.timestamp.isoformat(),
            "method":           self.method,
            "url":              self.url,
            "protocol":         self.protocol,
            "status_code":      self.status_code,
            "response_size":    self.response_size,
            "referrer":         self.referrer,
            "user_agent":       self.user_agent,
            "destination_ip":   self.destination_ip,
            "destination_port": self.destination_port,
            "duration_ms":      self.duration_ms,
            "source":           self.source.value,
        }


@dataclass
class IPDRRecord:
    """IP Detail Record — tracks per-IP session metadata."""
    source_ip:         str
    destination_ip:    str
    source_port:       int
    destination_port:  int
    protocol:          str
    start_time:        datetime
    end_time:          Optional[datetime] = None
    bytes_sent:        int                = 0
    bytes_received:    int                = 0
    packets_sent:      int                = 0
    packets_received:  int                = 0
    session_id:        Optional[str]      = None
    domain:            Optional[str]      = None
    url_count:         int                = 0
    flags:             List[str]          = field(default_factory=list)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip":        self.source_ip,
            "destination_ip":   self.destination_ip,
            "source_port":      self.source_port,
            "destination_port": self.destination_port,
            "protocol":         self.protocol,
            "start_time":       self.start_time.isoformat(),
            "end_time":         self.end_time.isoformat() if self.end_time else None,
            "bytes_sent":       self.bytes_sent,
            "bytes_received":   self.bytes_received,
            "packets_sent":     self.packets_sent,
            "packets_received": self.packets_received,
            "session_id":       self.session_id,
            "domain":           self.domain,
            "url_count":        self.url_count,
            "duration_seconds": self.duration_seconds,
            "flags":            self.flags,
        }


@dataclass
class URLRequest:
    """Extracted URL request from any source (log / PCAP / IPDR)."""
    source_ip:    str
    timestamp:    datetime
    full_url:     str
    method:       str         = "GET"
    host:         str         = ""
    path:         str         = ""
    query_string: str         = ""
    fragment:     str         = ""
    status_code:  Optional[int]   = None
    user_agent:   Optional[str]   = None
    referrer:     Optional[str]   = None
    source:       LogSource       = LogSource.CUSTOM
    raw:          Optional[str]   = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip":    self.source_ip,
            "timestamp":    self.timestamp.isoformat(),
            "full_url":     self.full_url,
            "method":       self.method,
            "host":         self.host,
            "path":         self.path,
            "query_string": self.query_string,
            "fragment":     self.fragment,
            "status_code":  self.status_code,
            "user_agent":   self.user_agent,
            "referrer":     self.referrer,
            "source":       self.source.value,
        }


@dataclass
class SnortAlert:
    """Represents a single Snort IDS alert."""
    timestamp:       datetime
    src_ip:          str
    dst_ip:          str
    src_port:        Optional[int]  = None
    dst_port:        Optional[int]  = None
    protocol:        str            = "TCP"
    # Rule identification
    generator_id:    int            = 1
    signature_id:    int            = 0
    signature_rev:   int            = 0
    # Alert metadata
    message:         str            = ""
    classification:  Optional[str]  = None
    priority:        Optional[int]  = None
    # Packet-level info
    ttl:             Optional[int]  = None
    ip_len:          Optional[int]  = None
    dgm_len:         Optional[int]  = None
    tos:             Optional[str]  = None
    tcp_flags:       Optional[str]  = None
    tcp_seq:         Optional[str]  = None
    tcp_ack:         Optional[str]  = None
    tcp_win:         Optional[str]  = None
    # Raw
    raw:             Optional[str]  = None

    @property
    def rule_id(self) -> str:
        return f"{self.generator_id}:{self.signature_id}:{self.signature_rev}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp":      self.timestamp.isoformat(),
            "src_ip":         self.src_ip,
            "dst_ip":         self.dst_ip,
            "src_port":       self.src_port,
            "dst_port":       self.dst_port,
            "protocol":       self.protocol,
            "rule_id":        self.rule_id,
            "generator_id":   self.generator_id,
            "signature_id":   self.signature_id,
            "signature_rev":  self.signature_rev,
            "message":        self.message,
            "classification": self.classification,
            "priority":       self.priority,
            "ttl":            self.ttl,
            "ip_len":         self.ip_len,
            "dgm_len":        self.dgm_len,
            "tos":            self.tos,
            "tcp_flags":      self.tcp_flags,
            "tcp_seq":        self.tcp_seq,
            "tcp_ack":        self.tcp_ack,
            "tcp_win":        self.tcp_win,
        }


@dataclass
class CollectionResult:
    """Aggregated result from the data collection pipeline."""
    http_logs:     List[HTTPLogEntry] = field(default_factory=list)
    ipdr_records:  List[IPDRRecord]   = field(default_factory=list)
    url_requests:  List[URLRequest]   = field(default_factory=list)
    snort_alerts:  List[SnortAlert]   = field(default_factory=list)
    errors:        List[str]          = field(default_factory=list)
    source_files:  List[str]          = field(default_factory=list)

    @property
    def total_records(self) -> int:
        return (len(self.http_logs) + len(self.ipdr_records)
                + len(self.url_requests) + len(self.snort_alerts))

    def summary(self) -> Dict[str, Any]:
        return {
            "http_log_entries":  len(self.http_logs),
            "ipdr_records":      len(self.ipdr_records),
            "url_requests":      len(self.url_requests),
            "snort_alerts":      len(self.snort_alerts),
            "total_records":     self.total_records,
            "source_files":      self.source_files,
            "errors":            len(self.errors),
        }
