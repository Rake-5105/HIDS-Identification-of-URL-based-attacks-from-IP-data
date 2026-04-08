from __future__ import annotations

import re
from urllib.parse import unquote, urlparse


_REGEX_RULES = {
    "SQL Injection": [
        re.compile(r"(union|select|insert|update|delete|--|#|'\s*or\s*'1'='1)", re.IGNORECASE),
        re.compile(r"(?:'|\")\s*or\s+\d+\s*=\s*\d+", re.IGNORECASE),
        re.compile(r"'\s*or\s*'1'\s*=\s*'1", re.IGNORECASE),
        re.compile(r"\bunion\s+select\b", re.IGNORECASE),
        re.compile(r"--|/\*|\*/", re.IGNORECASE),
        re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
        re.compile(r"\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.IGNORECASE),
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"</\s*script\s*>", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"onload\s*=", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
    ],
    "Command Injection": [
        re.compile(r"(;|&&|\||`)\s*(ls|whoami|cat|id|ping|sleep)\b", re.IGNORECASE),
        re.compile(r"(;|\|\||&&)\s*(cat|bash|sh|cmd|powershell|wget|curl|nc|netcat)\b", re.IGNORECASE),
        re.compile(r"\b(?:cmd|exec|command|shell)\s*=", re.IGNORECASE),
        re.compile(r"\$\(|`.+`", re.IGNORECASE),
    ],
    "Remote File Inclusion (RFI)": [
        re.compile(r"\b(?:file|page|path|include|template|view)=https?://", re.IGNORECASE),
        re.compile(r"\b(?:file|page|path|include|template|view)=\\\\", re.IGNORECASE),
        re.compile(r"https?://[^\s?#]+\.(?:php|jsp|asp|aspx|cgi)(?:\?|$)", re.IGNORECASE),
    ],
    "Local File Inclusion (LFI)": [
        re.compile(r"\b(?:file|page|path|include|template|view)=.*(?:/etc/passwd|boot\.ini|windows/win\.ini|/proc/self/environ)", re.IGNORECASE),
        re.compile(r"\b(?:file|page|path|include|template|view)=.*(?:\.\./|%2e%2e%2f)", re.IGNORECASE),
    ],
    "Server-Side Request Forgery (SSRF)": [
        re.compile(r"(?:https?|ftp|gopher|file)://(?:127\.0\.0\.1|localhost|0\.0\.0\.0)", re.IGNORECASE),
        re.compile(r"(?:https?|ftp|gopher|file)://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)", re.IGNORECASE),
        re.compile(r"(?:https?|ftp|gopher|file)://(?:\[::1\]|::1)", re.IGNORECASE),
        re.compile(r"(?:https?|ftp|gopher|file)://(?:2130706433|0x7f000001)(?::\d+)?(?:/|$)", re.IGNORECASE),
        re.compile(r"(?:https?|ftp|gopher|file)://(?:\d{8,10}|0x[0-9a-f]{6,8})(?::\d+)?(?:/|$)", re.IGNORECASE),
    ],
    "HTTP Parameter Pollution": [
        re.compile(r"(?:\?|&)([^=&]+)=[^&]*(?:&\1=)", re.IGNORECASE),
    ],
    "XML External Entity Injection (XXE)": [
        re.compile(r"<!doctype", re.IGNORECASE),
        re.compile(r"<!entity", re.IGNORECASE),
        re.compile(r"<!doctype\s+[^>]*\[\s*<!entity", re.IGNORECASE),
        re.compile(r"<!entity\s+\w+\s+system\s+['\"](?:file|http|ftp)://", re.IGNORECASE),
        re.compile(r"%3c!doctype|%3c!entity", re.IGNORECASE),
    ],
    "LDAP Injection": [
        re.compile(r"\(&|\(\||\*\)|\)\(", re.IGNORECASE),
        re.compile(r"\b(?:uid|cn|ou|dc)\s*=\s*\*", re.IGNORECASE),
    ],
    "HTTP Header Injection": [
        re.compile(r"(?:%0d%0a|\r\n|\n|\r)(?:location:|set-cookie:)", re.IGNORECASE),
    ],
    "Directory Traversal": [
        re.compile(r"\.\./|\.\\\\", re.IGNORECASE),
        re.compile(r"%2e%2e%2f|%2e%2e%5c", re.IGNORECASE),
        re.compile(r"\\\\windows\\\\system32", re.IGNORECASE),
    ],
    "Web Shell Upload": [
        re.compile(r"(?:cmd|shell|backdoor|webshell)\.(?:php|jsp|asp|aspx|cgi)\b", re.IGNORECASE),
        re.compile(r"(?:upload|file)=.*\.(?:php|jsp|asp|aspx|cgi)\b", re.IGNORECASE),
    ],
}


_ATTACK_PRIORITY = {
    "SQL Injection": 1,
    "Command Injection": 2,
    "Web Shell Upload": 3,
    "Remote File Inclusion (RFI)": 4,
    "Local File Inclusion (LFI)": 5,
    "Server-Side Request Forgery (SSRF)": 6,
    "XML External Entity Injection (XXE)": 7,
    "LDAP Injection": 8,
    "HTTP Header Injection": 9,
    "Cross-Site Scripting (XSS)": 10,
    "Directory Traversal": 11,
    "HTTP Parameter Pollution": 12,
}


_TYPO_SQUAT_HOST_PATTERNS = [
    re.compile(r"(^|\.)xn--", re.IGNORECASE),
    re.compile(r"(?:paypa1|g00gle|micr0soft|faceb00k|amaz0n|app1e|arnazon)", re.IGNORECASE),
]

_TYPO_BRANDS = [
    "amazon", "paypal", "google", "microsoft", "apple",
    "facebook", "instagram", "netflix", "bank", "icici", "hdfc"
]

_TYPO_LURE_WORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "support", "billing", "recovery", "auth", "wallet"
]

_OFFICIAL_DOMAIN_SUFFIXES = [
    "amazon.com", "paypal.com", "google.com", "microsoft.com", "apple.com",
    "facebook.com", "instagram.com", "netflix.com"
]


def _is_typosquatting_host(host: str) -> bool:
    h = str(host or "").lower().strip().strip(".")
    if not h:
        return False

    if any(h == sfx or h.endswith(f".{sfx}") for sfx in _OFFICIAL_DOMAIN_SUFFIXES):
        return False

    has_brand = any(b in h for b in _TYPO_BRANDS)
    has_lure = any(w in h for w in _TYPO_LURE_WORDS)
    has_hyphen = "-" in h

    # Typical phishing-style hostnames combine a known brand with lure words,
    # often as hyphenated domains (e.g., login-amazon-account.com).
    if has_brand and has_lure and has_hyphen:
        return True

    return False


def _decode_variants(text: str) -> list[str]:
    variants = []
    value = str(text or "")
    seen = set()

    for _ in range(3):
        if value not in seen:
            seen.add(value)
            variants.append(value)
        new_value = unquote(value)
        if new_value == value:
            break
        value = new_value

    return variants


def _is_unknown_suspicious(url_text: str, combined_text: str) -> bool:
    value = str(combined_text or "")
    url_value = str(url_text or "")

    suspicious_keywords = [
        "exec", "system", "shell", "cmd", "payload", "base64", "${jndi", "../../",
        "<svg", "onmouseover", "document.cookie", "@import", "file://", "gopher://",
    ]
    keyword_hits = sum(1 for k in suspicious_keywords if k in value)

    special_chars = sum(1 for ch in value if not ch.isalnum() and not ch.isspace())
    special_ratio = (special_chars / max(len(value), 1))

    encoded_markers = value.count("%") + value.count("\\x") + value.count("\\u00")

    # High-risk but previously unmatched payloads should be reviewed as suspicious.
    if keyword_hits >= 2:
        return True
    if special_ratio >= 0.35 and len(value) >= 40:
        return True
    if encoded_markers >= 6:
        return True
    if ("http://" in value or "https://" in value) and ("localhost" in value or "169.254." in value):
        return True
    if len(url_value) > 300:
        return True

    return False


def _counter_value(counter, source_ip: str) -> int:
    if counter is None:
        return 0
    if isinstance(counter, (int, float)):
        return int(counter)
    if isinstance(counter, dict):
        return int(counter.get(source_ip, 0)) if source_ip else 0
    return 0


def detect_regex_attack(
    url: str,
    payload: str | None = None,
    source_ip: str | None = None,
    method: str = "GET",
    headers: dict | None = None,
    request_count: dict | int | float | None = None,
    login_attempts: dict | int | float | None = None,
) -> tuple[str, str]:
    if url is None:
        value = ""
    elif isinstance(url, str):
        value = url
    else:
        value = str(url)

    url_variants = _decode_variants(value)
    payload_variants = _decode_variants(str(payload or ""))
    combined = " ".join(url_variants + payload_variants).strip()

    matched: list[tuple[int, str, str]] = []
    for attack_type, patterns in _REGEX_RULES.items():
        for pattern in patterns:
            if pattern.search(combined):
                matched.append((_ATTACK_PRIORITY.get(attack_type, 999), attack_type, pattern.pattern))

    if matched:
        matched.sort(key=lambda x: x[0])
        _, attack_type, pattern = matched[0]
        return attack_type, pattern

    method_upper = str(method or "GET").upper()
    headers = headers or {}
    source_ip = str(source_ip or "")

    if _counter_value(request_count, source_ip) > 100:
        return "Denial of Service (DoS)", "request_count[ip] > 100"

    header_keys = {str(k).lower() for k in headers.keys()}
    if method_upper == "POST" and "csrf_token" not in header_keys:
        return "CSRF (Possible)", "POST without csrf_token"

    if _counter_value(login_attempts, source_ip) > 10:
        return "Credential Stuffing / Brute Force", "login_attempts[ip] > 10"

    # Heuristic-only typosquatting checks when no explicit payload pattern matched.
    try:
        parsed = urlparse(url_variants[-1] if url_variants else value)
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""

    if host:
        for pattern in _TYPO_SQUAT_HOST_PATTERNS:
            if pattern.search(host):
                return "Typosquatting / URL Spoofing", pattern.pattern

        if _is_typosquatting_host(host):
            return "Typosquatting / URL Spoofing", "brand+lure-hyphen-host"

    if _is_unknown_suspicious(url_variants[-1] if url_variants else value, combined.lower()):
        return "Suspicious Behavior", "unknown-anomaly-signals"

    return "Normal", ""
