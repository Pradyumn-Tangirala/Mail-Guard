"""
url_analysis/__init__.py
=========================
Public surface of the url_analysis package.

All real implementation lives in scanner.py.
Import from here — never import directly from scanner.py in pipeline code.
"""

from url_analysis.scanner import (
    extract_urls,
    is_ip_based_url,
    is_shortened_url,
    get_domain,
    get_domain_age_days,
    is_newly_registered,
    resolve_redirects,
    check_blacklist,
    score_url,
    scan_body,
    SHORTENER_DOMAINS,
    DOMAIN_AGE_THRESHOLD_DAYS,
)

__all__ = [
    "extract_urls",
    "is_ip_based_url",
    "is_shortened_url",
    "get_domain",
    "get_domain_age_days",
    "is_newly_registered",
    "resolve_redirects",
    "check_blacklist",
    "score_url",
    "scan_body",
    "SHORTENER_DOMAINS",
    "DOMAIN_AGE_THRESHOLD_DAYS",
]
