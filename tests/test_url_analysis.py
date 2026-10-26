import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from url_analysis import get_domain, is_ip_based_url


# Regression: the old code used lstrip("www."), which strips the *characters*
# w and . from the left, so web.com became eb.com and w3schools.com 3schools.com.
@pytest.mark.parametrize("url, expected", [
    ("https://web.com/login", "web.com"),
    ("https://w3schools.com/", "w3schools.com"),
    ("https://www.web.com/", "web.com"),
    ("https://Example.COM:8443/path", "example.com"),
])
def test_get_domain_strips_only_www_prefix(url, expected):
    assert get_domain(url) == expected


def test_userinfo_trick_is_detected_as_ip_based():
    # Everything before '@' is userinfo; the browser actually connects to 1.2.3.4.
    url = "http://paypal.com@1.2.3.4/login"
    assert get_domain(url) == "1.2.3.4"
    assert is_ip_based_url(url)


def test_ipv6_host_is_detected_as_ip_based():
    assert is_ip_based_url("http://[2001:db8::1]/login")
    assert is_ip_based_url("https://[2001:db8::1]:8443/login")


def test_ipv4_host_with_port_is_detected():
    assert is_ip_based_url("https://203.0.113.5:8080/track?id=123")


def test_normal_domain_is_not_ip_based():
    assert not is_ip_based_url("https://example.com/login")
    assert not is_ip_based_url("http://1.2.3.4.example.com/")  # IP-looking subdomain


def test_malformed_url_does_not_raise():
    assert get_domain("http://[unclosed/login") is None
    assert not is_ip_based_url("http://[unclosed/login")
