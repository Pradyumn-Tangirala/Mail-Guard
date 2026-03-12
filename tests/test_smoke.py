import pytest
import os
import sys

# Add project root to path for testing
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing import parse_raw_email, clean_text
from threat_scoring import classify_threat, ThreatLevel

def test_preprocessing_clean_text():
    raw_html = "<p>Hello <b>World</b>!</p>"
    cleaned = clean_text(raw_html)
    assert cleaned == "Hello World !"

def test_parse_raw_email():
    raw_email = "From: user@example.com\nSubject: Test\n\nBody content"
    parsed = parse_raw_email(raw_email)
    assert parsed["subject"] == "Test"
    assert parsed["body"] == "Body content"

def test_classify_threat():
    # Verify classification bands
    assert classify_threat(10) == ThreatLevel.SAFE
    assert classify_threat(40) == ThreatLevel.SUSPICIOUS
    assert classify_threat(65) == ThreatLevel.PHISHING
    assert classify_threat(90) == ThreatLevel.MALWARE

if __name__ == "__main__":
    pytest.main([__file__])
