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
class CollectionResult:
    """Aggregated result from the data collection pipeline."""
    http_logs:   List[HTTPLogEntry] = field(default_factory=list)
    ipdr_records: List[IPDRRecord]  = field(default_factory=list)
    url_requests: List[URLRequest]  = field(default_factory=list)
    errors:       List[str]         = field(default_factory=list)
    source_files: List[str]         = field(default_factory=list)

    @property
    def total_records(self) -> int:
        return len(self.http_logs) + len(self.ipdr_records) + len(self.url_requests)

    def summary(self) -> Dict[str, Any]:
        return {
            "http_log_entries":  len(self.http_logs),
            "ipdr_records":      len(self.ipdr_records),
            "url_requests":      len(self.url_requests),
            "total_records":     self.total_records,
            "source_files":      self.source_files,
            "errors":            len(self.errors),
        }
