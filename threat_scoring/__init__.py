"""
threat_scoring/__init__.py
===========================
Public surface of the threat_scoring package.

All real implementation lives in engine.py.
Import from here — never import directly from engine.py in pipeline code.
"""

from threat_scoring.engine import (
    ThreatLevel,
    aggregate_scores,
    score_to_100,
    classify_threat,
    evaluate_rules,
    generate_report,
    to_siem_json,
)

__all__ = [
    "ThreatLevel",
    "aggregate_scores",
    "score_to_100",
    "classify_threat",
    "evaluate_rules",
    "generate_report",
    "to_siem_json",
]
