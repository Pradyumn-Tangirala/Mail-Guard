"""
api/app.py
===========
MailGuard FastAPI application.

Endpoints
─────────
  POST /analyze   — Full threat pipeline on raw .eml text
  POST /predict   — Backward-compatible simple prediction (legacy frontend)
  GET  /health    — Liveness probe (k8s / load-balancer compatible)
  GET  /version   — Package + model version info

Run with:
  uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload
Or via main.py CLI:
  python main.py api --port 8000
"""

import logging
import sys
import os
from datetime import datetime, timezone

import uvicorn  # type: ignore
from fastapi import FastAPI, HTTPException, Request, status  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from fastapi.responses import JSONResponse  # type: ignore
from pydantic import BaseModel, Field  # type: ignore

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path when run as a module
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

logger = logging.getLogger("mailguard.api")

# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

# Upper bound on submitted email size (~1 MB of text). Oversized input is
# rejected with 422 before any parsing, so one request cannot tie up the server.
MAX_EMAIL_CHARS = 1_000_000


class AnalyzeRequest(BaseModel):
    email: str = Field(
        ...,
        min_length=10,
        max_length=MAX_EMAIL_CHARS,
        description="Raw email text (full .eml format, including headers and body).",
        examples=["From: sender@example.com\r\nSubject: Hello\r\n\r\nBody text here."],
    )
    email_id: str = Field(
        default="",
        max_length=256,
        description="Optional caller-supplied email identifier (e.g. Message-ID). "
                    "Auto-generated UUID if omitted.",
    )


class PredictRequest(BaseModel):
    """Legacy schema — kept for backward compatibility with existing frontend."""
    email: str = Field(..., min_length=1, max_length=MAX_EMAIL_CHARS, description="Email body text.")


def _cors_origins() -> list:
    """Allowed browser origins, from MAILGUARD_CORS_ORIGINS (comma-separated)."""
    raw = os.getenv("MAILGUARD_CORS_ORIGINS", "http://localhost:8501")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""

    app = FastAPI(
        title="MailGuard Threat Detection API",
        description=(
            "Prototype email phishing detection pipeline. "
            "Accepts raw .eml text and returns an ECS-style JSON threat report."
        ),
        version="0.2.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS: only listed browser origins; no cookies/credentials ──────────────
    # The Streamlit dashboard calls the API server-side (httpx), so CORS does
    # not affect it; this only governs JavaScript running in a browser.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Global exception handler (returns structured JSON, never HTML) ─────────
    # Exception details are logged server-side only. The client gets a generic
    # message plus a request id it can quote, so internal paths, library
    # versions or input fragments are never echoed back.
    @app.exception_handler(Exception)
    async def _global_error(request: Request, exc: Exception):
        import uuid
        request_id = str(uuid.uuid4())
        logger.exception("Unhandled error [request_id=%s] on %s %s",
                         request_id, request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "request_id": request_id,
                "path": request.url.path,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            },
        )

    # ── Lazy pipeline import (avoids circular import at module load) ───────────
    def _get_pipeline():
        import importlib
        return importlib.import_module("main").run_pipeline

    def _get_legacy():
        """Load the pickled model + vectorizer for the /predict legacy route."""
        import pickle, pathlib
        artifacts = pathlib.Path(_PROJECT_ROOT) / "models" / "artifacts"
        model_path = artifacts / "model.pkl"
        vec_path   = artifacts / "vectorizer.pkl"
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        with open(vec_path, "rb") as f:
            vectorizer = pickle.load(f)
        return model, vectorizer

    # ==========================================================================
    # Routes
    # ==========================================================================

    @app.get("/health", tags=["System"], summary="Liveness probe")
    async def health():
        """Returns 200 OK when the API is running. Used by load balancers and k8s."""
        return {
            "status": "ok",
            "version": "0.2.0",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }

    @app.get("/version", tags=["System"], summary="Version info")
    async def version():
        """Returns API and pipeline component version strings."""
        return {
            "api":      "0.2.0",
            "pipeline": "mailguard-soc-v1",
            "python":   sys.version,
        }

    @app.post("/analyze", tags=["Threat Detection"], summary="Full pipeline analysis")
    async def analyze(req: AnalyzeRequest):
        """
        Run the complete MailGuard threat detection pipeline on a raw email.

        Pipeline stages executed:
          1. Preprocessing  — parse headers, clean body
          2. URL Analysis   — extract, classify, and score all URLs
          3. Header Analysis — SPF / DKIM / DMARC / spoofing
          4. ML Inference   — GradientBoosting NLP classifier
          5. Threat Scoring — weighted aggregation + rule engine

        Returns a SIEM-ready threat report (ECS-aligned JSON).
        """
        import uuid
        email_id = req.email_id.strip() or str(uuid.uuid4())

        try:
            run_pipeline = _get_pipeline()
            report = run_pipeline(req.email, email_id=email_id)
        except NotImplementedError as exc:
            # A pipeline module is still a stub — give a clear message
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail=f"Pipeline stage not yet implemented: {exc}",
            )
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Model artifact not found. Run train_model.py first. ({exc})",
            )

        return report

    @app.post("/predict", tags=["Legacy"], summary="Simple phishing/safe prediction")
    async def predict(req: PredictRequest):
        """
        Backward-compatible endpoint for the legacy HTML frontend (frontend/index.html).

        Returns:
            {"prediction": "Safe Email" | "Phishing Email", "confidence": float}
        """
        try:
            model, vectorizer = _get_legacy()
        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Model not found: {exc}. Run train_model.py first.",
            )

        from preprocessing import clean_text, normalize_for_model  # match training
        vec        = vectorizer.transform([normalize_for_model(clean_text(req.email))])
        pred       = model.predict(vec)[0]
        proba      = model.predict_proba(vec)[0]
        confidence = float(proba[1] if pred == 1 else proba[0])
        label      = "Safe Email" if pred == 0 else "Phishing Email"

        return {"prediction": label, "confidence": float(f"{confidence:.4f}")}

    return app


# ---------------------------------------------------------------------------
# Module-level app instance (for uvicorn auto-reload: uvicorn api.app:app)
# ---------------------------------------------------------------------------
app = create_app()


# ---------------------------------------------------------------------------
# Programmatic launcher (called by main.py CLI)
# ---------------------------------------------------------------------------
def run(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Start the uvicorn server programmatically."""
    uvicorn.run(
        "api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    run()
