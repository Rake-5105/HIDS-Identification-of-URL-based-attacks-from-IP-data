from __future__ import annotations

import re
from urllib.parse import unquote


_REGEX_RULES = {
    "SQL Injection": [
        re.compile(r"(?:'|\")\s*or\s+\d+\s*=\s*\d+", re.IGNORECASE),
        re.compile(r"\bunion\s+select\b", re.IGNORECASE),
        re.compile(r"--|/\*|\*/", re.IGNORECASE),
        re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
    ],
    "Cross-Site Scripting (XSS)": [
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
    ],
    "Directory Traversal": [
        re.compile(r"\.\./|\.\.\\\\", re.IGNORECASE),
        re.compile(r"%2e%2e%2f|%2e%2e%5c", re.IGNORECASE),
        re.compile(r"/etc/passwd|\\\\windows\\\\system32", re.IGNORECASE),
    ],
}


def detect_regex_attack(url: str) -> tuple[str, str]:
    if url is None:
        value = ""
    elif isinstance(url, str):
        value = url
    else:
        value = str(url)

    decoded = unquote(value)

    for attack_type, patterns in _REGEX_RULES.items():
        for pattern in patterns:
            if pattern.search(decoded):
                return attack_type, pattern.pattern

    return "Normal", ""
