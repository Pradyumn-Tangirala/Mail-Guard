import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import main
import url_analysis.scanner as scanner
from preprocessing import extract_features, parse_raw_email


@pytest.fixture(autouse=True)
def no_whois(monkeypatch):
    """Keep tests offline and fast: WHOIS returns 'unknown age' (fails open)."""
    monkeypatch.setattr(scanner, "get_domain_age_days", lambda domain: None)


HTML_EMAIL = (
    "From: \"IT Support\" <support@example.test>\n"
    "Subject: Password expiry\n"
    "MIME-Version: 1.0\n"
    "Content-Type: text/html; charset=\"utf-8\"\n"
    "\n"
    "<html><body><p>Your password expires today.</p>"
    "<a href=\"http://1.2.3.4/login\">Click here</a></body></html>\n"
)


def _rule_ids(report):
    return [r["rule_id"] for r in report["mailguard"]["triggered_rules"]]


def test_link_only_in_href_triggers_url_001():
    report = main.run_pipeline(HTML_EMAIL, email_id="html-href")
    assert "http://1.2.3.4/login" in report["mailguard"]["details"]["url"]["ip_based"]
    assert "URL-001" in _rule_ids(report)


def test_nlp_input_still_has_html_tags_and_href_stripped():
    # The URL fix must not change what the classifier sees.
    features = extract_features(parse_raw_email(HTML_EMAIL))
    assert features["clean_body"] == "Your password expires today. Click here"
