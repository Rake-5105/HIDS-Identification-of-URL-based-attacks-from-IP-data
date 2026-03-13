"""
URL Parsing Module — Core Parser
==================================
Converts raw URL strings (or URLRequest objects from Module 1) into
fully-structured ParsedURL objects with all components broken out.
"""

import logging
import os
import re
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, unquote_plus

from .models import ParsedURL, QueryParam

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default port table
# ---------------------------------------------------------------------------
_SCHEME_PORTS: dict = {
    "http":  80,
    "https": 443,
    "ftp":   21,
    "ftps":  990,
}


def _infer_scheme(raw_url: str) -> str:
    """Return the scheme from a URL, defaulting to 'http'."""
    low = raw_url.lower()
    if low.startswith("https"):
        return "https"
    if low.startswith("ftp"):
        return "ftp"
    return "http"


def _safe_port(port_str: Optional[str], scheme: str) -> Optional[int]:
    if port_str:
        try:
            return int(port_str)
        except ValueError:
            pass
    return None


def _file_extension(path: str) -> str:
    """Extract file extension from path (without leading dot), e.g. 'php'."""
    base = os.path.basename(path.split("?")[0].split("#")[0])
    _, ext = os.path.splitext(base)
    return ext.lstrip(".").lower()


def _path_segments(path: str) -> List[str]:
    """Split a URL path into non-empty segments."""
    return [seg for seg in path.split("/") if seg]


# ---------------------------------------------------------------------------
# URLParser
# ---------------------------------------------------------------------------

class URLParser:
    """
    Parses individual URL strings into ParsedURL objects.

    Handles:
      - Fully-qualified URLs  (https://example.com/path?k=v)
      - Relative URLs         (/admin/login.php?user=admin)
      - Bare paths            (../../../etc/passwd)
      - Percent-encoded chars (decoded before storage)
      - Multi-value query params (key appears more than once)
    """

    # Regex to detect a URL that is already fully qualified
    _ABSOLUTE_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", re.ASCII)

    def parse(
        self,
        raw_url:     str,
        source_ip:   str,
        timestamp:   datetime,
        method:      str             = "GET",
        status_code: Optional[int]   = None,
        user_agent:  Optional[str]   = None,
        referrer:    Optional[str]   = None,
        source:      str             = "unknown",
    ) -> Optional[ParsedURL]:
        """
        Parse *raw_url* and return a ParsedURL, or None if unparseable.

        Parameters
        ----------
        raw_url     : Raw URL string from the log line.
        source_ip   : Client IP address.
        timestamp   : When the request occurred.
        method      : HTTP method string.
        status_code : HTTP response status code.
        user_agent  : User-Agent header value.
        referrer    : Referer header value.
        source      : Where this record came from (e.g. 'apache').
        """
        if not raw_url or not raw_url.strip():
            return None

        raw_url = raw_url.strip()

        # ── Prepend scheme if missing so urlparse works correctly ──────────
        if not self._ABSOLUTE_URL_RE.match(raw_url):
            work_url = "http://placeholder" + (
                raw_url if raw_url.startswith("/") else "/" + raw_url
            )
            inferred_scheme = "http"
            inferred_host   = ""
            inferred_port   = None
        else:
            work_url        = raw_url
            inferred_scheme = _infer_scheme(raw_url)
            inferred_host   = ""
            inferred_port   = None

        try:
            parsed = urlparse(work_url)
        except Exception as exc:
            logger.debug("urlparse failed for %r: %s", raw_url, exc)
            return None

        # ── Extract components ─────────────────────────────────────────────
        if inferred_host == "":
            netloc = parsed.netloc or ""
            # strip userinfo (user:pass@host)
            if "@" in netloc:
                netloc = netloc.rsplit("@", 1)[1]
            if ":" in netloc:
                host_part, port_part = netloc.rsplit(":", 1)
            else:
                host_part, port_part = netloc, ""
            host   = host_part if host_part != "placeholder" else ""
            port   = _safe_port(port_part, inferred_scheme) if port_part else None
            scheme = parsed.scheme or inferred_scheme
        else:
            host   = inferred_host
            port   = inferred_port
            scheme = inferred_scheme

        path            = unquote_plus(parsed.path   or "/")
        query_string    = parsed.query   or ""
        fragment        = parsed.fragment or ""
        file_extension  = _file_extension(path)
        segments        = _path_segments(path)

        # ── Query params ───────────────────────────────────────────────────
        query_params: List[QueryParam] = []
        for key, value in parse_qsl(query_string, keep_blank_values=True):
            query_params.append(QueryParam(
                key=unquote_plus(key),
                value=unquote_plus(value),
            ))

        # ── Normalise method ───────────────────────────────────────────────
        method_clean = (method or "GET").upper().strip()

        return ParsedURL(
            source_ip      = source_ip,
            timestamp      = timestamp,
            raw_url        = raw_url,
            scheme         = scheme,
            host           = host,
            port           = port,
            path           = path,
            path_segments  = segments,
            query_string   = query_string,
            query_params   = query_params,
            fragment       = fragment,
            file_extension = file_extension,
            method         = method_clean,
            status_code    = status_code,
            user_agent     = user_agent,
            referrer       = referrer,
            source         = source,
        )

    def parse_many(
        self,
        records: list,           # list of URLRequest (from Module 1)
    ) -> Tuple[List[ParsedURL], int, List[str]]:
        """
        Parse a list of URLRequest objects (from Module 1's CollectionResult).

        Returns
        -------
        (parsed_urls, skipped_count, error_messages)
        """
        parsed:  List[ParsedURL] = []
        skipped: int             = 0
        errors:  List[str]       = []

        for rec in records:
            try:
                result = self.parse(
                    raw_url     = getattr(rec, "full_url", str(rec)),
                    source_ip   = getattr(rec, "source_ip",   "0.0.0.0"),
                    timestamp   = getattr(rec, "timestamp",   datetime.utcnow()),
                    method      = getattr(rec, "method",      "GET"),
                    status_code = getattr(rec, "status_code", None),
                    user_agent  = getattr(rec, "user_agent",  None),
                    referrer    = getattr(rec, "referrer",    None),
                    source      = getattr(rec, "source",      "unknown")
                                  if not hasattr(getattr(rec, "source", None), "value")
                                  else getattr(rec, "source").value,
                )
                if result:
                    parsed.append(result)
                else:
                    skipped += 1
            except Exception as exc:
                msg = f"Error parsing record: {exc}"
                logger.warning(msg)
                errors.append(msg)
                skipped += 1

        logger.info("URLParser: %d parsed, %d skipped, %d errors",
                    len(parsed), skipped, len(errors))
        return parsed, skipped, errors
