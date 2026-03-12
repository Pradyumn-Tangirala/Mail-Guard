"""
url_analysis/scanner.py
========================
Extracts, classifies, and scores URLs found in email bodies.

Detection signals:
  - IP-based URLs          (no hostname — high suspicion)
  - Known URL shorteners   (obfuscation indicator)
  - Newly registered domains via WHOIS  (< 30 days old)
  - Blacklist membership   (stub — wired for future threat feed)

All scoring is additive and capped at 1.0.
WHOIS lookups are performed lazily and cached per domain within a scan session.
"""

import re
import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Matches http:// and https:// URLs, including query strings and fragments.
_URL_RE = re.compile(
    r"https?://"
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)

# IP-address host in URL (IPv4 only; IPv6 in URLs is rare in email).
_IP_HOST_RE = re.compile(
    r"^https?://(\d{1,3}\.){3}\d{1,3}(?:[:/]|$)",
    re.IGNORECASE,
)

# Known URL shortener domains.
SHORTENER_DOMAINS: frozenset = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.io",
    "rebrand.ly", "is.gd", "buff.ly", "adf.ly", "tiny.cc", "shorturl.at",
    "cutt.ly", "rb.gy", "snip.ly", "bl.ink", "t2m.io", "x.co", "v.gd",
    "tr.im", "su.pr", "twurl.nl", "budurl.com", "cli.gs", "ff.im",
})

# Domain age threshold — domains younger than this are flagged.
DOMAIN_AGE_THRESHOLD_DAYS = 30

# Score weights
_SCORE_IP_URL      = 0.55   # Bare-IP URL is a very strong phishing signal
_SCORE_SHORTENED   = 0.30   # Shortened URL is obfuscation
_SCORE_NEW_DOMAIN  = 0.40   # Newly registered domain


# ===========================================================================
# PUBLIC API
# ===========================================================================

def extract_urls(email_body: str) -> list:
    """
    Extract all unique http/https URLs from an email body string.

    Returns:
        Ordered list of unique URL strings (preserving first-occurrence order).
    """
    if not email_body:
        return []

    urls = _URL_RE.findall(email_body)

    # Deduplicate while preserving insertion order
    seen: set = set()
    unique: list = []
    for url in urls:
        # Strip trailing punctuation that regex may have captured
        url = url.rstrip(")>,.'\"")
        if url and url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def is_ip_based_url(url: str) -> bool:
    """
    Return True if the URL uses a bare IPv4 address instead of a hostname.

    Examples flagged:
      http://192.168.1.1/login
      https://203.0.113.5:8080/track?id=123
    """
    return bool(_IP_HOST_RE.match(url))


def is_shortened_url(url: str) -> bool:
    """
    Return True if the URL hostname belongs to a known URL shortener service.

    Examples flagged:
      https://bit.ly/3xYzAb
      http://tinyurl.com/abc123
    """
    domain = _get_bare_domain(url)
    return domain in SHORTENER_DOMAINS if domain else False


def get_domain(url: str) -> Optional[str]:
    """
    Extract the bare domain (no 'www.' prefix, lowercase) from a URL.

    Returns None if the URL cannot be parsed.
    """
    return _get_bare_domain(url)


def get_domain_age_days(domain: str) -> Optional[int]:
    """
    Query WHOIS to find how many days ago a domain was registered.

    Returns:
        int   — age in days if lookup succeeds.
        None  — if WHOIS data is unavailable or the domain cannot be parsed.

    Notes:
        - Requires `pip install python-whois`.
        - Results are cached per domain within a process session via @lru_cache.
        - Failure mode is *open*: None means "don't penalize."
    """
    return _cached_domain_age(domain)


def is_newly_registered(
    domain: str,
    threshold_days: int = DOMAIN_AGE_THRESHOLD_DAYS,
) -> bool:
    """
    Return True if the domain was registered less than `threshold_days` ago.

    Fails open: returns False if WHOIS data is unavailable.
    """
    age = get_domain_age_days(domain)
    if age is None:
        return False
    return age < threshold_days


def resolve_redirects(url: str) -> str:
    """
    Follow HTTP redirect chains and return the final destination URL.

    Current implementation: stub — returns the URL unchanged.
    TODO: Replace with `requests.head(url, allow_redirects=True, timeout=5).url`
          wrapped in a try/except for production use.
    """
    return url


def check_blacklist(url: str) -> bool:
    """
    Check whether a URL appears on a known threat intelligence blacklist.

    Current implementation: stub — always returns False.
    TODO: Wire to PhishTank API, SURBL DNS blocklist, or a local YAML feed.
    """
    return False


def score_url(url: str) -> float:
    """
    Compute a suspicion score in [0.0, 1.0] for a single URL.

    Scoring:
      +0.55  — IP-based URL  (highest: legitimate mail never uses bare IPs)
      +0.30  — Shortened URL (obfuscation)
      +0.40  — Newly registered domain (< 30 days via WHOIS)

    Signals are additive and capped at 1.0.
    Blacklisted URLs bypass scoring and return 1.0 directly.
    """
    if check_blacklist(url):
        return 1.0

    score = 0.0
    domain = get_domain(url)

    if is_ip_based_url(url):
        logger.debug("IP-based URL: %s", url)
        score += _SCORE_IP_URL

    if is_shortened_url(url):
        logger.debug("Shortened URL: %s", url)
        score += _SCORE_SHORTENED

    # Only run WHOIS on resolvable hostnames (not IPs or shorteners — those
    # are already penalized and WHOIS on shorteners targets the *service* domain)
    if domain and not is_ip_based_url(url) and not is_shortened_url(url):
        if is_newly_registered(domain):
            logger.debug("Newly registered domain (<30 days): %s", domain)
            score += _SCORE_NEW_DOMAIN

    return round(min(score, 1.0), 4)


def scan_body(email_body: str) -> dict:
    """
    Perform a complete URL scan on an email body string.

    This is the high-level function `main.py` should call — it wraps all
    individual checks into one structured result.

    Returns:
        {
            "urls_found":       list[str],   all extracted URLs
            "ip_based":         list[str],   URLs using bare IP addresses
            "shortened":        list[str],   URLs via known shorteners
            "newly_registered": list[str],   domains registered < 30 days ago
            "blacklisted":      list[str],   URLs on threat feeds
            "url_scores":       dict[str, float],  per-URL score
            "max_score":        float,       highest score across all URLs
        }
    """
    urls = extract_urls(email_body)

    result: dict = {
        "urls_found":       urls,
        "ip_based":         [],
        "shortened":        [],
        "newly_registered": [],
        "blacklisted":      [],
        "url_scores":       {},
        "max_score":        0.0,
    }

    for url in urls:
        final_url = resolve_redirects(url)
        domain    = get_domain(final_url)

        if is_ip_based_url(final_url):
            result["ip_based"].append(final_url)

        if is_shortened_url(final_url):
            result["shortened"].append(final_url)

        if check_blacklist(final_url):
            result["blacklisted"].append(final_url)

        if domain and is_newly_registered(domain):
            result["newly_registered"].append(domain)

        result["url_scores"][url] = score_url(final_url)

    if result["url_scores"]:
        result["max_score"] = max(result["url_scores"].values())

    return result


# ===========================================================================
# PRIVATE HELPERS
# ===========================================================================

def _get_bare_domain(url: str) -> Optional[str]:
    """Parse and return the lowercase bare hostname from a URL."""
    try:
        netloc = urlparse(url).netloc.lower()
        if not netloc:
            return None
        # Strip port number (e.g. example.com:8080 → example.com)
        netloc = netloc.split(":")[0]
        # Strip www. prefix for normalisation
        return netloc.lstrip("www.") or None
    except Exception:
        return None


@lru_cache(maxsize=256)
def _cached_domain_age(domain: str) -> Optional[int]:
    """
    WHOIS lookup with per-process in-memory cache (LRU, max 256 domains).

    The cache prevents repeated expensive WHOIS calls for the same domain
    during a single pipeline run or API request burst.
    """
    try:
        import whois  # python-whois  (pip install python-whois)
        w = whois.whois(domain)
        creation_date = w.creation_date

        # WHOIS libraries sometimes return a list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None

        # Ensure timezone-aware comparison
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(tz=timezone.utc) - creation_date).days
        logger.debug("WHOIS domain=%s  age=%d days", domain, age_days)
        return age_days

    except ImportError:
        logger.warning(
            "python-whois not installed. Run: pip install python-whois  "
            "(Domain age checks are disabled until then.)"
        )
        return None
    except Exception as exc:
        logger.debug("WHOIS lookup failed for '%s': %s", domain, exc)
        return None
