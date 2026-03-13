"""
URL Parsing Module — Normalizer
=================================
Cleans and standardises ParsedURL objects after initial parsing:
  - Lowercases scheme and host
  - Collapses duplicate slashes and dot-segments in paths
  - Strips common tracking/session query parameters (configurable)
  - Decodes double-encoded percent sequences
  - Resolves default ports
"""

import re
import logging
from typing import List, Optional, Set
from urllib.parse import unquote, quote

from .models import ParsedURL, QueryParam

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common tracking / noise query-parameter keys to strip before analysis.
# Override via URLNormalizer(strip_params={...}).
# ---------------------------------------------------------------------------
DEFAULT_STRIP_PARAMS: Set[str] = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "yclid",
    "sessionid", "session_id", "sid",
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
    "_ga", "_gid", "_gl",
}

# Regex: repeated slashes (but keep leading double-slash of protocol-relative)
_MULTI_SLASH_RE = re.compile(r"/{2,}")

# Regex: double percent-encoding  (%25xx → %xx)
_DOUBLE_ENCODE_RE = re.compile(r"%25([0-9a-fA-F]{2})")


def _resolve_dot_segments(path: str) -> str:
    """Resolve '.' and '..' segments in a URL path (RFC 3986 §5.2.4)."""
    segments: List[str] = []
    for seg in path.split("/"):
        if seg == "..":
            if segments:
                segments.pop()
        elif seg != ".":
            segments.append(seg)
    result = "/".join(segments)
    if not result.startswith("/"):
        result = "/" + result
    return result


def _decode_double_encoding(value: str) -> str:
    """Decode %25xx → %xx (one level of double-encoding)."""
    return _DOUBLE_ENCODE_RE.sub(r"%\1", value)


class URLNormalizer:
    """
    Applies a series of normalization passes to a ParsedURL in-place
    (returns a new ParsedURL — originals are not mutated).

    Parameters
    ----------
    strip_params : set of query-param keys to remove (tracking params etc.)
                   Pass an empty set to disable stripping.
    collapse_path_slashes : whether to collapse //+ → /
    resolve_dots          : whether to resolve ./.. path segments
    decode_double_encoding: whether to undo double percent-encoding
    """

    def __init__(
        self,
        strip_params:             Optional[Set[str]] = None,
        collapse_path_slashes:    bool = True,
        resolve_dots:             bool = True,
        decode_double_encoding:   bool = True,
    ):
        self.strip_params           = strip_params if strip_params is not None \
                                      else DEFAULT_STRIP_PARAMS
        self.collapse_path_slashes  = collapse_path_slashes
        self.resolve_dots           = resolve_dots
        self.decode_double_encoding = decode_double_encoding

    # ── Public API ────────────────────────────────────────────────────────

    def normalize(self, url: ParsedURL) -> ParsedURL:
        """Return a normalised copy of *url*."""
        import copy
        n = copy.deepcopy(url)
        self._normalize_scheme_host(n)
        self._normalize_path(n)
        self._normalize_query(n)
        return n

    def normalize_many(self, urls: List[ParsedURL]) -> List[ParsedURL]:
        """Normalize a list of ParsedURL objects."""
        result = [self.normalize(u) for u in urls]
        logger.info("URLNormalizer: normalized %d URLs", len(result))
        return result

    # ── Private passes ────────────────────────────────────────────────────

    def _normalize_scheme_host(self, url: ParsedURL) -> None:
        url.scheme = url.scheme.lower().strip()
        url.host   = url.host.lower().strip()
        # Remove default port to keep URLs canonical
        if url.port == 80  and url.scheme == "http":
            url.port = None
        if url.port == 443 and url.scheme == "https":
            url.port = None

    def _normalize_path(self, url: ParsedURL) -> None:
        path = url.path or "/"

        if self.decode_double_encoding:
            path = _decode_double_encoding(path)

        if self.collapse_path_slashes:
            # Preserve leading slash; collapse internal multiples
            leading = "/" if path.startswith("/") else ""
            path = leading + _MULTI_SLASH_RE.sub("/", path.lstrip("/"))

        if self.resolve_dots:
            path = _resolve_dot_segments(path)

        url.path = path or "/"
        # Re-derive segments and extension after normalization
        url.path_segments = [s for s in path.split("/") if s]
        import os
        base = os.path.basename(path)
        _, ext = os.path.splitext(base)
        url.file_extension = ext.lstrip(".").lower()

    def _normalize_query(self, url: ParsedURL) -> None:
        if not self.strip_params:
            return
        # Case-insensitive strip
        strip_lower = {k.lower() for k in self.strip_params}
        url.query_params = [
            p for p in url.query_params
            if p.key.lower() not in strip_lower
        ]
        # Rebuild raw query string from kept params
        url.query_string = "&".join(
            f"{quote(p.key, safe='')}={quote(p.value, safe='')}"
            for p in url.query_params
        )
