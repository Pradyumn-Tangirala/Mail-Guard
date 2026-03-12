"""
threat_scoring/engine.py
=========================
Aggregates signals from all pipeline layers into a final 0-100 Threat Score
and emits a SIEM-ready structured JSON log.

Output schema loosely follows Elastic Common Schema (ECS) so it maps cleanly
into Elasticsearch, Splunk, Sentinel, or any CEF/LEEF-compatible SIEM without
custom field transforms.

Score Weights
─────────────
  NLP model probability  →  40 pts max   (primary classifier)
  URL scan max score     →  35 pts max   (obfuscation / malicious links)
  Header threat score    →  25 pts max   (auth failures + spoofing)

Classification Bands
────────────────────
   0 – 29   SAFE
  30 – 54   SUSPICIOUS
  55 – 79   PHISHING
  80 – 100  MALWARE

Rule Engine
───────────
Rules are evaluated independently against the raw signals dict.
Each triggered rule contributes a human-readable string to the
`triggered_rules` array in the JSON report. Rules never alter the
numeric score — scoring and rule-firing are separate concerns so
future rules can be added without touching the weight system.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat classification
# ---------------------------------------------------------------------------

class ThreatLevel(Enum):
    SAFE       = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING   = "PHISHING"
    MALWARE    = "MALWARE"

    @property
    def severity(self) -> int:
        """ECS-compatible integer severity (1=low … 4=critical)."""
        return {
            ThreatLevel.SAFE:       1,
            ThreatLevel.SUSPICIOUS: 2,
            ThreatLevel.PHISHING:   3,
            ThreatLevel.MALWARE:    4,
        }[self]

    @property
    def color(self) -> str:
        """Terminal / dashboard color hint."""
        return {
            ThreatLevel.SAFE:       "green",
            ThreatLevel.SUSPICIOUS: "yellow",
            ThreatLevel.PHISHING:   "orange",
            ThreatLevel.MALWARE:    "red",
        }[self]


# ---------------------------------------------------------------------------
# Score weights  (must sum to 1.0)
# ---------------------------------------------------------------------------
_W_NLP    = 0.40
_W_URL    = 0.35
_W_HEADER = 0.25
assert abs(_W_NLP + _W_URL + _W_HEADER - 1.0) < 1e-9, "Score weights must sum to 1.0"

# Classification thresholds (inclusive lower bound)
_THRESHOLDS = [
    (80, ThreatLevel.MALWARE),
    (55, ThreatLevel.PHISHING),
    (30, ThreatLevel.SUSPICIOUS),
    (0,  ThreatLevel.SAFE),
]


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule is a tuple of:
#   (rule_id, description_template, predicate)
# The predicate receives the full signals dict and returns True if the rule
# fires. Keep predicates pure (no side-effects, no network calls).

_RULES: list[tuple] = [
    # ── URL rules ──────────────────────────────────────────────────────────────
    (
        "URL-001",
        "IP-based URL detected: {detail}",
        lambda s: bool(s.get("url_scan", {}).get("ip_based")),
        lambda s: s["url_scan"]["ip_based"],
    ),
    (
        "URL-002",
        "URL shortener detected: {detail}",
        lambda s: bool(s.get("url_scan", {}).get("shortened")),
        lambda s: s["url_scan"]["shortened"],
    ),
    (
        "URL-003",
        "Newly registered domain (<30 days): {detail}",
        lambda s: bool(s.get("url_scan", {}).get("newly_registered")),
        lambda s: s["url_scan"]["newly_registered"],
    ),
    (
        "URL-004",
        "URL on threat intelligence blacklist: {detail}",
        lambda s: bool(s.get("url_scan", {}).get("blacklisted")),
        lambda s: s["url_scan"]["blacklisted"],
    ),
    (
        "URL-005",
        "High URL threat score (>=0.70): max_score={detail}",
        lambda s: s.get("url_score", 0.0) >= 0.70,
        lambda s: round(s.get("url_score", 0.0), 3),
    ),
    # ── Header / auth rules ────────────────────────────────────────────────────
    (
        "HDR-001",
        "SPF authentication failure: {detail}",
        lambda s: not s.get("spf", {}).get("passed", True),
        lambda s: s.get("spf", {}).get("raw", "n/a"),
    ),
    (
        "HDR-002",
        "DKIM signature failure: {detail}",
        lambda s: not s.get("dkim", {}).get("passed", True),
        lambda s: s.get("dkim", {}).get("raw", "n/a"),
    ),
    (
        "HDR-003",
        "DMARC alignment failure — From/Return-Path mismatch: {detail}",
        lambda s: not s.get("dmarc", {}).get("aligned", True),
        lambda s: (
            f"{s.get('dmarc', {}).get('from_domain', '?')} vs "
            f"{s.get('dmarc', {}).get('return_path_domain', '?')}"
        ),
    ),
    (
        "HDR-004",
        "Spoofing indicator: {detail}",
        lambda s: bool(s.get("spoofing_flags")),
        lambda s: s.get("spoofing_flags", []),
    ),
    (
        "HDR-005",
        "High composite header threat score (>=0.60): score={detail}",
        lambda s: s.get("header_score", 0.0) >= 0.60,
        lambda s: round(s.get("header_score", 0.0), 3),
    ),
    # ── NLP / ML rules ─────────────────────────────────────────────────────────
    (
        "NLP-001",
        "ML model high-confidence phishing prediction (>=0.80): probability={detail}",
        lambda s: s.get("nlp_score", 0.0) >= 0.80,
        lambda s: round(s.get("nlp_score", 0.0), 3),
    ),
    (
        "NLP-002",
        "ML model moderate phishing signal (0.50-0.79): probability={detail}",
        lambda s: 0.50 <= s.get("nlp_score", 0.0) < 0.80,
        lambda s: round(s.get("nlp_score", 0.0), 3),
    ),
    # ── Composite / cross-layer rules ──────────────────────────────────────────
    (
        "CRIT-001",
        "CRITICAL: All three layers triggered simultaneously (NLP + URL + Header)",
        lambda s: (
            s.get("nlp_score", 0.0) >= 0.50
            and s.get("url_score", 0.0) >= 0.30
            and s.get("header_score", 0.0) >= 0.30
        ),
        lambda s: None,   # no extra detail needed
    ),
    (
        "CRIT-002",
        "CRITICAL: Blacklisted URL combined with spoofing indicators",
        lambda s: (
            bool(s.get("url_scan", {}).get("blacklisted"))
            and bool(s.get("spoofing_flags"))
        ),
        lambda s: None,
    ),
]


# ===========================================================================
# PUBLIC API
# ===========================================================================

def aggregate_scores(signals: dict) -> float:
    """
    Combine layer scores into a single weighted float in [0.0, 1.0].

    Expected signal keys:
      nlp_score    float  0.0–1.0  (from models.run_inference)
      url_score    float  0.0–1.0  (max of url_scan["url_scores"].values())
      header_score float  0.0–1.0  (from header_analysis.header_threat_score)

    Returns:
      Weighted average, clamped to [0.0, 1.0].
    """
    nlp    = float(signals.get("nlp_score",    0.0))
    url    = float(signals.get("url_score",    0.0))
    header = float(signals.get("header_score", 0.0))

    raw = (_W_NLP * nlp) + (_W_URL * url) + (_W_HEADER * header)
    return round(min(max(raw, 0.0), 1.0), 6)


def score_to_100(normalized: float) -> int:
    """Convert a [0.0, 1.0] normalized score to a 0-100 integer Threat Score."""
    return round(normalized * 100)


def classify_threat(score: float) -> ThreatLevel:
    """
    Map a normalized score (0.0–1.0) or a 0-100 integer to a ThreatLevel.

    Accepts both ranges transparently.
    """
    # Normalise to 0-100
    s = score_to_100(score) if score <= 1.0 else int(score)
    for threshold, level in _THRESHOLDS:
        if s >= threshold:
            return level
    return ThreatLevel.SAFE


def evaluate_rules(signals: dict) -> list[dict]:
    """
    Evaluate all registered detection rules against the signals dict.

    Returns:
        List of triggered rule dicts:
        [{"rule_id": str, "description": str}, ...]
    """
    triggered = []
    for rule_id, description_tpl, predicate, detail_fn in _RULES:
        try:
            if predicate(signals):
                detail = detail_fn(signals)
                description = (
                    description_tpl.format(detail=detail)
                    if detail is not None
                    else description_tpl
                )
                triggered.append({"rule_id": rule_id, "description": description})
        except Exception as exc:
            logger.debug("Rule %s evaluation error: %s", rule_id, exc)
    return triggered


def generate_report(
    email_id: str,
    signals: dict,
    verdict: ThreatLevel,
    *,
    source_ip: str = "",
    recipient: str = "",
) -> dict:
    """
    Build a SIEM-ready structured threat report.

    The schema loosely follows Elastic Common Schema (ECS) so it ingests
    directly into Elasticsearch / Kibana SIEM or Splunk without custom
    field mappings. LEEF and CEF serializers can wrap the returned dict.

    Args:
        email_id:   Unique identifier for the email (Message-ID or UUID).
        signals:    Full signals dict from run_pipeline() Stage 5.
        verdict:    ThreatLevel enum value.
        source_ip:  Optional — IP of the sending MTA (from Received headers).
        recipient:  Optional — envelope recipient address.

    Returns:
        dict — the full threat report (JSON-serialisable).
    """
    normalized_score = aggregate_scores(signals)
    threat_score_100 = score_to_100(normalized_score)
    triggered_rules  = evaluate_rules(signals)
    now_utc          = datetime.now(tz=timezone.utc)

    # ── ECS-style report structure ─────────────────────────────────────────────
    report: dict[str, Any] = {
        # ECS top-level fields
        "@timestamp": now_utc.isoformat(),
        "event": {
            "created":   now_utc.isoformat(),
            "kind":      "alert",
            "category":  ["email", "threat"],
            "type":      ["indicator"],
            "severity":  verdict.severity,      # int 1–4
            "risk_score": threat_score_100,     # 0–100 (ECS risk_score field)
            "dataset":   "mailguard.threat",
            "provider":  "mailguard",
            "action":    verdict.value.lower(),
        },

        # MailGuard-specific namespace
        "mailguard": {
            # ── Core verdict ──────────────────────────────────────────────────
            "email_id":       email_id,
            "threat_score":   threat_score_100,          # 0-100 for SIEM
            "classification": verdict.value,             # SAFE / SUSPICIOUS / PHISHING / MALWARE
            "color":          verdict.color,             # dashboard hint

            # ── Rule engine output ────────────────────────────────────────────
            "triggered_rules":      triggered_rules,
            "triggered_rule_count": len(triggered_rules),

            # ── Raw signal scalars (for SIEM dashboard charting) ──────────────
            "signals": {
                "nlp_score":    round(signals.get("nlp_score",    0.0), 4),
                "url_score":    round(signals.get("url_score",    0.0), 4),
                "header_score": round(signals.get("header_score", 0.0), 4),
                "normalized":   normalized_score,
            },

            # ── Per-layer details (drill-down in SIEM) ────────────────────────
            "details": {
                "header": {
                    "spf":            signals.get("spf",  {}),
                    "dkim":           signals.get("dkim", {}),
                    "dmarc":          signals.get("dmarc", {}),
                    "spoofing_flags": signals.get("spoofing_flags", []),
                },
                "url": {
                    "total_urls":       len(signals.get("url_scan", {}).get("urls_found", [])),
                    "ip_based":         signals.get("url_scan", {}).get("ip_based", []),
                    "shortened":        signals.get("url_scan", {}).get("shortened", []),
                    "newly_registered": signals.get("url_scan", {}).get("newly_registered", []),
                    "blacklisted":      signals.get("url_scan", {}).get("blacklisted", []),
                    "per_url_scores":   signals.get("url_scan", {}).get("url_scores", {}),
                },
                "nlp": {
                    "model":           signals.get("nlp_model_name", "phishing_classifier_v1"),
                    "label":           signals.get("nlp_label", "unknown"),
                    "probability":     round(signals.get("nlp_score", 0.0), 4),
                },
            },
        },

        # ── Optional network context (useful for SIEM correlation) ─────────────
        "source": {"ip": source_ip} if source_ip else {},
        "destination": {"user": {"email": recipient}} if recipient else {},
    }

    return report


def to_siem_json(report: dict, indent: int = 2) -> str:
    """
    Serialise a threat report to a clean JSON string for SIEM ingestion.

    Handles non-serialisable types (e.g. datetime objects, Enum values, sets).
    """
    def _default(obj: Any) -> Any:
        if isinstance(obj, ThreatLevel):
            return obj.value
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")

    return json.dumps(report, indent=indent, default=_default, ensure_ascii=False)
