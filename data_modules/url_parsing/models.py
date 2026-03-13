"""
URL Parsing Module — Data Models
=================================
Extended data models produced by the URL Parsing Module (Module 2).
Builds on the `URLRequest` from data_collection and adds fully-structured,
security-relevant parsed fields.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class HTTPMethod(Enum):
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    DELETE  = "DELETE"
    HEAD    = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH   = "PATCH"
    TRACE   = "TRACE"
    CONNECT = "CONNECT"
    UNKNOWN = "UNKNOWN"


@dataclass
class QueryParam:
    """A single key=value pair from a query string."""
    key:   str
    value: str

    def to_dict(self) -> Dict[str, str]:
        return {"key": self.key, "value": self.value}


@dataclass
class ParsedURL:
    """
    Fully structured representation of a single HTTP request URL,
    produced by the URL Parsing Module.

    Fields
    ------
    source_ip       IP address of the client making the request.
    timestamp       When the request was observed.
    method          HTTP verb (GET, POST, …).
    scheme          Protocol scheme (http / https).
    host            Target hostname or IP.
    port            Destination port (default 80/443 inferred from scheme).
    path            URL path component (e.g. /admin/login.php).
    path_segments   Individual path segments split on '/'.
    query_string    Raw query string (everything after '?').
    query_params    Parsed list of QueryParam objects.
    fragment        URL fragment (after '#').
    file_extension  Extension of the last path segment (e.g. 'php', 'asp').
    status_code     HTTP response status code.
    user_agent      Verbatim User-Agent header string.
    referrer        HTTP Referer header string.
    source          Origin of this record (apache / nginx / pcap / …).
    raw_url         Original unmodified URL string.
    """

    # Core identity
    source_ip:      str
    timestamp:      datetime
    raw_url:        str

    # Parsed components
    scheme:         str             = "http"
    host:           str             = ""
    port:           Optional[int]   = None
    path:           str             = "/"
    path_segments:  List[str]       = field(default_factory=list)
    query_string:   str             = ""
    query_params:   List[QueryParam] = field(default_factory=list)
    fragment:       str             = ""
    file_extension: str             = ""

    # Request metadata
    method:         str             = "GET"
    status_code:    Optional[int]   = None
    user_agent:     Optional[str]   = None
    referrer:       Optional[str]   = None
    source:         str             = "unknown"

    # ── Convenience properties ────────────────────────────────────────────

    @property
    def is_https(self) -> bool:
        return self.scheme.lower() == "https"

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        return 443 if self.is_https else 80

    @property
    def query_param_keys(self) -> List[str]:
        return [p.key for p in self.query_params]

    @property
    def query_param_count(self) -> int:
        return len(self.query_params)

    @property
    def path_depth(self) -> int:
        return len([s for s in self.path_segments if s])

    def get_param(self, key: str) -> Optional[str]:
        """Return the first value for *key*, or None."""
        for p in self.query_params:
            if p.key.lower() == key.lower():
                return p.value
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip":      self.source_ip,
            "timestamp":      self.timestamp.isoformat(),
            "raw_url":        self.raw_url,
            "scheme":         self.scheme,
            "host":           self.host,
            "port":           self.port,
            "effective_port": self.effective_port,
            "path":           self.path,
            "path_segments":  self.path_segments,
            "path_depth":     self.path_depth,
            "query_string":   self.query_string,
            "query_params":   [p.to_dict() for p in self.query_params],
            "query_param_count": self.query_param_count,
            "fragment":       self.fragment,
            "file_extension": self.file_extension,
            "method":         self.method,
            "status_code":    self.status_code,
            "user_agent":     self.user_agent,
            "referrer":       self.referrer,
            "source":         self.source,
        }


@dataclass
class ParseResult:
    """Aggregated output from the URL Parsing pipeline."""
    parsed_urls:    List[ParsedURL] = field(default_factory=list)
    skipped:        int             = 0
    errors:         List[str]       = field(default_factory=list)
    source_tag:     str             = ""

    @property
    def total(self) -> int:
        return len(self.parsed_urls)

    def summary(self) -> Dict[str, Any]:
        methods: Dict[str, int] = {}
        schemes: Dict[str, int] = {}
        exts:    Dict[str, int] = {}
        for p in self.parsed_urls:
            methods[p.method]         = methods.get(p.method, 0) + 1
            schemes[p.scheme]         = schemes.get(p.scheme, 0) + 1
            ext = p.file_extension or "(none)"
            exts[ext]                 = exts.get(ext, 0) + 1
        return {
            "total_parsed":    self.total,
            "skipped":         self.skipped,
            "errors":          len(self.errors),
            "methods":         methods,
            "schemes":         schemes,
            "file_extensions": exts,
            "source_tag":      self.source_tag,
        }
