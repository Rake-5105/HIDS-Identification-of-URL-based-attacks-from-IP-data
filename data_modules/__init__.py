"""
data_modules — top-level package for the URL-based Attack Identification project.

Modules
-------
  data_collection  — Module 1: ingest HTTP logs, PCAP, IPDR, Snort alerts
  url_parsing      — Module 2: parse & normalise URLs into structured fields
"""

from . import data_collection
from . import url_parsing

__all__ = ["data_collection", "url_parsing"]
