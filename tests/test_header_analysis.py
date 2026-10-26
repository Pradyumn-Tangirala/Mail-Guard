import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from header_analysis import check_dmarc, parse_headers


def _email(from_addr, auth_results, extra_headers=""):
    # SPF fails in every case, so DMARC can only pass through DKIM alignment.
    return (
        f"From: {from_addr}\n"
        f"Return-Path: <bounce@unrelated.test>\n"
        f"Authentication-Results: mx.example.com; spf=fail; {auth_results}\n"
        f"{extra_headers}"
        f"Subject: test\n\nbody\n"
    )


def test_dkim_pass_for_unrelated_domain_does_not_pass_dmarc():
    # A valid signature from evil.com says nothing about mail claiming to be paypal.com.
    headers = parse_headers(_email("PayPal <service@paypal.com>", "dkim=pass header.d=evil.com"))
    dmarc = check_dmarc(headers)
    assert headers["dkim_domain"] == "evil.com"
    assert dmarc["dkim_aligned"] is False
    assert dmarc["passed"] is False


def test_dkim_pass_from_subdomain_aligns_with_from_domain():
    headers = parse_headers(_email("PayPal <service@paypal.com>", "dkim=pass header.d=mail.paypal.com"))
    dmarc = check_dmarc(headers)
    assert dmarc["dkim_aligned"] is True
    assert dmarc["passed"] is True


def test_dkim_domain_falls_back_to_dkim_signature_header():
    raw = _email(
        "Example <news@example.org>", "dkim=pass",
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=sel1; bh=abc=; b=xyz=\n",
    )
    headers = parse_headers(raw)
    assert headers["dkim_domain"] == "example.org"
    assert check_dmarc(headers)["passed"] is True


def test_dkim_fail_never_passes_even_if_aligned():
    headers = parse_headers(_email("PayPal <service@paypal.com>", "dkim=fail header.d=paypal.com"))
    assert check_dmarc(headers)["passed"] is False
