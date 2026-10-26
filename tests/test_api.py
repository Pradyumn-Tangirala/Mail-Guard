import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient

import main
from api.app import MAX_EMAIL_CHARS, create_app


def test_oversized_email_is_rejected_with_422():
    client = TestClient(create_app())
    resp = client.post("/analyze", json={"email": "x" * (MAX_EMAIL_CHARS + 1)})
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["type"] == "string_too_long"


def test_oversized_predict_input_is_rejected_with_422():
    client = TestClient(create_app())
    resp = client.post("/predict", json={"email": "x" * (MAX_EMAIL_CHARS + 1)})
    assert resp.status_code == 422


def test_unhandled_error_returns_generic_500_without_details(monkeypatch):
    def boom(raw_email, email_id="unknown"):
        raise RuntimeError("secret internal detail: C:/server/path/config.py")

    monkeypatch.setattr(main, "run_pipeline", boom)
    client = TestClient(create_app(), raise_server_exceptions=False)
    resp = client.post("/analyze", json={"email": "From: a@b.test\n\nhello there"})

    assert resp.status_code == 500
    body = resp.json()
    assert body["error"] == "Internal server error"
    assert body["request_id"]
    assert "secret" not in resp.text and "RuntimeError" not in resp.text


def test_cors_allows_only_configured_origins(monkeypatch):
    monkeypatch.setenv("MAILGUARD_CORS_ORIGINS", "http://localhost:8501")
    client = TestClient(create_app())
    preflight = {"Access-Control-Request-Method": "POST"}

    ok = client.options("/analyze", headers={"Origin": "http://localhost:8501", **preflight})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:8501"
    assert "access-control-allow-credentials" not in ok.headers

    bad = client.options("/analyze", headers={"Origin": "https://evil.test", **preflight})
    assert "access-control-allow-origin" not in bad.headers
