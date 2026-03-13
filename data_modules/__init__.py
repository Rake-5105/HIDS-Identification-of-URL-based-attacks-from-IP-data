"""
data_modules — top-level package for the URL-based Attack Identification project.

Modules
-------
  data_collection  — Module 1: ingest HTTP logs, PCAP, IPDR, Snort alerts
  url_parsing      — Module 2: parse & normalise URLs into structured fields
  feature_extraction — Module 3: extract URL security features
  classification   — Module 4: hybrid detection & classification
"""

from . import data_collection
from . import url_parsing
from . import feature_extraction
from . import classification

__all__ = ["data_collection", "url_parsing", "feature_extraction", "classification"]
