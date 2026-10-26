"""
header_analysis/analyzer.py
============================
Parses raw email strings and performs multi-signal authentication analysis.

Extracts: From, Return-Path, Reply-To, Received, SPF, DKIM
Checks:   SPF/DKIM/DMARC results, domain mismatches, display-name impersonation

All public functions accept the `headers` dict returned by `parse_headers()`.
"""

import re
import email as _email_lib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known brand names to check for display-name impersonation
# ---------------------------------------------------------------------------
_TRUSTED_BRANDS = frozenset({
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "bank", "irs", "fedex", "dhl", "ups", "chase", "citibank", "wellsfargo",
})


# ===========================================================================
# PUBLIC API
# ===========================================================================

def parse_headers(raw_email: str) -> dict:
    """
    Parse a raw email string and extract every security-relevant header field.

    Accepts either:
    - A full raw email (headers + body) — the standard case from preprocessing.
    - A pre-parsed dict — returned as-is so downstream callers are idempotent.

    Returns:
        {
            "from":         str,
            "return_path":  str,
            "reply_to":     str,
            "received":     list[str],
            "spf_raw":      str,   # e.g. "spf=pass" or "spf=not_found"
            "dkim_raw":     str,   # e.g. "dkim=fail" or "dkim=not_found"
            "dkim_domain":  str,   # DKIM signing domain (d=), "" if unknown
            "subject":      str,
            "message_id":   str,
        }
    """
    # Idempotent: already parsed
    if isinstance(raw_email, dict):
        return raw_email

    try:
        msg = _email_lib.message_from_string(raw_email)
    except Exception as exc:
        logger.warning("Header parsing failed: %s", exc)
        return _empty_headers()

    return {
        "from":        msg.get("From", ""),
        "return_path": msg.get("Return-Path", ""),
        "reply_to":    msg.get("Reply-To", ""),
        "received":    msg.get_all("Received") or [],
        "spf_raw":     _extract_spf(msg),
        "dkim_raw":    _extract_dkim(msg),
        "dkim_domain": _extract_dkim_domain(msg),
        "subject":     msg.get("Subject", ""),
        "message_id":  msg.get("Message-ID", ""),
    }


def check_spf(headers: dict) -> dict:
    """
    Evaluate the SPF result embedded in parsed headers.

    Returns:
        {"raw": str, "passed": bool, "score": float}

    Score semantics (0.0 = clean, 1.0 = definite failure):
        pass     → 0.0
        softfail → 0.4
        neutral  → 0.2
        not_found→ 0.3
        fail     → 1.0
    """
    raw = headers.get("spf_raw", "spf=not_found").lower()
    if "pass" in raw and "fail" not in raw:
        return {"raw": raw, "passed": True, "score": 0.0}
    if "softfail" in raw:
        return {"raw": raw, "passed": False, "score": 0.4}
    if "neutral" in raw:
        return {"raw": raw, "passed": False, "score": 0.2}
    if "fail" in raw:
        return {"raw": raw, "passed": False, "score": 1.0}
    return {"raw": raw, "passed": False, "score": 0.3}   # not_found / unknown


def check_dkim(headers: dict) -> dict:
    """
    Evaluate the DKIM signature result embedded in parsed headers.

    Returns:
        {"raw": str, "passed": bool, "score": float}

    Score semantics:
        pass              → 0.0
        present_unverified→ 0.3
        not_found         → 0.4
        fail              → 0.8
    """
    raw = headers.get("dkim_raw", "dkim=not_found").lower()
    if "pass" in raw:
        return {"raw": raw, "passed": True,  "score": 0.0}
    if "present_unverified" in raw:
        return {"raw": raw, "passed": False, "score": 0.3}
    if "fail" in raw:
        return {"raw": raw, "passed": False, "score": 0.8}
    return {"raw": raw, "passed": False, "score": 0.4}   # not_found / unknown


def check_dmarc(headers: dict) -> dict:
    """
    Derive a DMARC-style assessment from SPF + DKIM results and domain alignment.

    Real DMARC also requires querying the DNS TXT record for _dmarc.<domain>
    (the published policy); this function does NOT do that. It performs a local
    *identifier alignment* check only. DMARC passes if EITHER:
    - SPF passed AND the Return-Path domain aligns with the From domain, OR
    - DKIM passed AND the DKIM signing domain (d=) aligns with the From domain.

    "Aligned" is relaxed: the same domain, or one is a subdomain of the other
    (mail.paypal.com aligns with paypal.com). This is a simplification of real
    relaxed alignment, which compares organisational domains via the Public
    Suffix List.

    Returns:
        {"passed": bool, "aligned": bool, "dkim_aligned": bool,
         "from_domain": str, "return_path_domain": str, "dkim_domain": str,
         "score": float}
        "aligned" is the From / Return-Path (SPF) alignment used by rule HDR-003.
    """
    spf   = check_spf(headers)
    dkim  = check_dkim(headers)

    from_domain        = _extract_domain(headers.get("from", ""))
    return_path_domain = _extract_domain(headers.get("return_path", ""))
    dkim_domain        = (headers.get("dkim_domain") or "").lower() or None

    aligned      = _domains_aligned(from_domain, return_path_domain)   # SPF alignment
    dkim_aligned = _domains_aligned(from_domain, dkim_domain)          # DKIM alignment

    # A DKIM pass only counts if the signing domain aligns with From:
    # anyone can validly sign mail as d=evil.com while showing From: paypal.com.
    passed = (spf["passed"] and aligned) or (dkim["passed"] and dkim_aligned)

    if passed:
        score = 0.0
    elif not aligned:
        score = 0.8   # misaligned domain is a strong signal
    else:
        score = 0.4   # alignment ok but auth failed

    return {
        "passed":              passed,
        "aligned":             aligned,
        "dkim_aligned":        dkim_aligned,
        "from_domain":         from_domain or "",
        "return_path_domain":  return_path_domain or "",
        "dkim_domain":         dkim_domain or "",
        "score":               score,
    }


def detect_spoofing(headers: dict) -> bool:
    """
    Multi-signal spoofing detector. Flags the email if ANY of the following hold:

    1. From-domain ≠ Return-Path domain  (envelope mismatch)
    2. Reply-To domain ≠ From domain     (reply hijacking)
    3. Display name contains a trusted brand but the From domain does not

    Returns:
        True if at least one spoofing indicator is present.
    """
    flags = _collect_spoofing_flags(headers)
    if flags:
        logger.debug("Spoofing flags detected: %s", flags)
    return bool(flags)


def get_spoofing_flags(headers: dict) -> list:
    """Return the full list of spoofing flag strings (useful for reports)."""
    return _collect_spoofing_flags(headers)


def header_threat_score(headers: dict) -> float:
    """
    Compute a single composite header threat score in [0.0, 1.0].

    Weights:
        SPF    25%
        DKIM   25%
        DMARC  30%
        Spoof  20%
    """
    spf   = check_spf(headers)
    dkim  = check_dkim(headers)
    dmarc = check_dmarc(headers)
    spoof = 1.0 if detect_spoofing(headers) else 0.0

    score = (
        spf["score"]   * 0.25
        + dkim["score"]  * 0.25
        + dmarc["score"] * 0.30
        + spoof          * 0.20
    )
    return float(f"{min(score, 1.0):.4f}")


# ===========================================================================
# PRIVATE HELPERS
# ===========================================================================

def _empty_headers() -> dict:
    return {
        "from": "", "return_path": "", "reply_to": "",
        "received": [], "spf_raw": "spf=not_found",
        "dkim_raw": "dkim=not_found", "dkim_domain": "", "subject": "", "message_id": "",
    }


def _extract_domain(address: str) -> Optional[str]:
    """Pull the domain portion out of 'Display Name <user@domain.tld>'."""
    if not address:
        return None
    match = re.search(r"@([\w.\-]+)", address)
    return match.group(1).lower().strip() if match else None


def _extract_spf(msg) -> str:
    """Pull the SPF verdict from Authentication-Results or Received-SPF."""
    for header_name in ("Authentication-Results", "Received-SPF"):
        value = msg.get(header_name, "")
        if not value:
            continue
        m = re.search(
            r"spf=(pass|fail|softfail|neutral|none|permerror|temperror)",
            value, re.IGNORECASE,
        )
        if m:
            return m.group(0).lower()
    return "spf=not_found"


def _extract_dkim(msg) -> str:
    """Pull the DKIM verdict from Authentication-Results or proxy-detect DKIM-Signature."""
    auth = msg.get("Authentication-Results", "")
    if auth:
        m = re.search(
            r"dkim=(pass|fail|none|permerror|temperror|neutral)",
            auth, re.IGNORECASE,
        )
        if m:
            return m.group(0).lower()
    if msg.get("DKIM-Signature"):
        return "dkim=present_unverified"
    return "dkim=not_found"


def _extract_dkim_domain(msg) -> str:
    """
    Pull the DKIM signing domain (d=).

    Prefers Authentication-Results "header.d=" (the receiving server's verified
    result, taking the passing signature if there are several), then falls back
    to the d= tag of the DKIM-Signature header (unverified).
    """
    auth = msg.get("Authentication-Results", "") or ""
    m = (re.search(r"dkim=pass\b[^;]*?header\.d=([\w.-]+)", auth, re.IGNORECASE)
         or re.search(r"header\.d=([\w.-]+)", auth, re.IGNORECASE))
    if m:
        return m.group(1).lower()
    sig = msg.get("DKIM-Signature", "") or ""
    m = re.search(r"(?:^|;)\s*d=([\w.-]+)", sig)
    return m.group(1).lower() if m else ""


def _domains_aligned(a: Optional[str], b: Optional[str]) -> bool:
    """Relaxed alignment: same domain, or one is a subdomain of the other."""
    if not a or not b:
        return False
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _collect_spoofing_flags(headers: dict) -> list:
    """Return a list of human-readable spoofing flag strings."""
    flags = []

    from_addr   = headers.get("from", "")
    return_path = headers.get("return_path", "")
    reply_to    = headers.get("reply_to", "")

    from_domain        = _extract_domain(from_addr)
    return_path_domain = _extract_domain(return_path)
    reply_to_domain    = _extract_domain(reply_to)

    # ── Flag 1: Envelope mismatch ──────────────────────────────────────────
    if from_domain and return_path_domain and from_domain != return_path_domain:
        flags.append(
            f"from_return_path_mismatch:"
            f"{from_domain} vs {return_path_domain}"
        )

    # ── Flag 2: Reply-To hijacking ─────────────────────────────────────────
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        flags.append(
            f"reply_to_hijack:{from_domain} vs {reply_to_domain}"
        )

    # ── Flag 3: Display-name brand impersonation ───────────────────────────
    display_match = re.match(r'^"?([^"<]+)"?\s*<', from_addr)
    if display_match and from_domain:
        display_name = display_match.group(1).strip().lower()
        for brand in _TRUSTED_BRANDS:
            if from_domain is not None and brand in display_name and brand not in str(from_domain):  # type: ignore
                flags.append(f"display_name_impersonation:{brand}")
                break   # one flag per email is enough

    return flags
