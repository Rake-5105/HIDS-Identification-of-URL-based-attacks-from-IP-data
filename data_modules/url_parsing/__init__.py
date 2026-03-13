"""
url_parsing — URL Parsing Module (Module 2)
============================================
Identification of URL-based Attacks from IP Data

Processes collected logs from Module 1 and extracts fully-structured
URL fields: scheme, host, port, path, path segments, query parameters,
file extension, HTTP method, status code, source IP, and timestamp.

Public API
----------
    from data_modules.url_parsing import URLParsingPipeline

    # --- Typical flow (after Module 1) ---
    from data_modules.data_collection import DataCollector
    from data_modules.url_parsing      import URLParsingPipeline

    collection_result = DataCollector().collect("sample_data/")
    pipeline          = URLParsingPipeline()
    parse_result      = pipeline.run(collection_result, tag="demo")
    pipeline.print_summary(parse_result)
    pipeline.save(parse_result, output_dir="output/", tag="demo")

    # --- Direct use ---
    from data_modules.url_parsing import URLParser
    from datetime import datetime

    parser = URLParser()
    parsed = parser.parse(
        raw_url     = "/search?q=hello+world",
        source_ip   = "203.0.113.5",
        timestamp   = datetime.now(),
        method      = "GET",
        status_code = 200,
    )
    print(parsed.path, parsed.query_params)
"""

from .pipeline   import URLParsingPipeline
from .parser     import URLParser
from .normalizer import URLNormalizer
from .models     import (
    ParsedURL,
    ParseResult,
    QueryParam,
    HTTPMethod,
)

__all__ = [
    "URLParsingPipeline",
    "URLParser",
    "URLNormalizer",
    "ParsedURL",
    "ParseResult",
    "QueryParam",
    "HTTPMethod",
]

__version__ = "1.0.0"
