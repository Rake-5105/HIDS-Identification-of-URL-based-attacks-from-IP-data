import re
from urllib.parse import unquote

def extract_features(url: str):

    if url is None:
        url = ""
    elif not isinstance(url, str):
        url = str(url)

    # Decode URL-encoded payloads before pattern checks.
    url = unquote(url)
    url = url.lower()

    features = {}

    # Length of URL
    features["url_length"] = len(url)

    # Count special characters
    features["special_characters"] = len(re.findall(r"[^\w]", url))

    # Detect common SQL injection markers with word boundaries.
    sql_patterns = [
        r"\bor\b\s+\d+=\d+",
        r"\bunion\b",
        r"\bselect\b",
        r"--",
        r"/\*",
        r"\*/",
    ]
    features["has_sql_keyword"] = int(any(re.search(p, url) for p in sql_patterns))

    # Detect common XSS patterns.
    xss_patterns = ["<script", "alert(", "onerror", "javascript:"]
    features["has_script"] = int(any(x in url for x in xss_patterns))

    # Detect directory traversal across slash styles.
    features["has_traversal"] = int("../" in url or "..\\" in url)

    return features