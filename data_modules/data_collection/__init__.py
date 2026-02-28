"""
data_collection — Data Collection Module
=========================================
Identification of URL-based Attacks from IP Data

Public API
----------
    from data_collection import DataCollector, CollectionConfig

    collector = DataCollector()                          # default config
    result    = collector.collect("/path/to/logs/")      # auto-detect & parse
    collector.print_summary(result)
    collector.save(result, tag="run_01")

    # Snort IDS alerts
    result  = collector.collect_snort("/var/log/snort/alert")
    summary = collector.snort_summary(result)
"""

from .collector    import DataCollector
from .config       import CollectionConfig
from .models       import (
    HTTPLogEntry,
    IPDRRecord,
    URLRequest,
    SnortAlert,
    CollectionResult,
    LogSource,
    Protocol,
)
from .log_parser      import HTTPLogParser
from .ipdr_collector  import IPDRCollector
from .pcap_analyzer   import PCAPAnalyzer
from .snort_collector import SnortCollector
from .log_ingestion   import LogIngestionPipeline

__all__ = [
    "DataCollector",
    "CollectionConfig",
    "HTTPLogEntry",
    "IPDRRecord",
    "URLRequest",
    "SnortAlert",
    "CollectionResult",
    "LogSource",
    "Protocol",
    "HTTPLogParser",
    "IPDRCollector",
    "PCAPAnalyzer",
    "SnortCollector",
    "LogIngestionPipeline",
]

__version__ = "1.1.0"
