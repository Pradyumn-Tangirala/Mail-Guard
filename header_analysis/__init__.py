"""
header_analysis/__init__.py
============================
Public surface of the header_analysis package.

All real implementation lives in analyzer.py.
Import from here — never import directly from analyzer.py in pipeline code.
"""

from .analyzer import (  # type: ignore
    parse_headers,
    check_spf,
    check_dkim,
    check_dmarc,
    detect_spoofing,
    get_spoofing_flags,
    header_threat_score,
)

__all__ = [
    "parse_headers",
    "check_spf",
    "check_dkim",
    "check_dmarc",
    "detect_spoofing",
    "get_spoofing_flags",
    "header_threat_score",
]
