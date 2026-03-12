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
  uvicorn api.app:app --host 0.0.0.0 --port 5000 --reload
Or via main.py CLI:
  python main.py api --port 5000
"""

import logging
import sys
import os
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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

class AnalyzeRequest(BaseModel):
    email: str = Field(
        ...,
        min_length=10,
        description="Raw email text (full .eml format, including headers and body).",
        examples=["From: sender@example.com\r\nSubject: Hello\r\n\r\nBody text here."],
    )
    email_id: str = Field(
        default="",
        description="Optional caller-supplied email identifier (e.g. Message-ID). "
                    "Auto-generated UUID if omitted.",
    )


class PredictRequest(BaseModel):
    """Legacy schema — kept for backward compatibility with existing frontend."""
    email: str = Field(..., min_length=1, description="Email body text.")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""

    app = FastAPI(
        title="MailGuard Threat Detection API",
        description=(
            "SOC-grade email threat detection pipeline. "
            "Accepts raw .eml text and returns a structured SIEM-ready threat report."
        ),
        version="0.2.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS (allow dashboard origin in dev; tighten in production) ────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Global exception handler (returns structured JSON, never HTML) ─────────
    @app.exception_handler(Exception)
    async def _global_error(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s %s", request.method, request.url)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": type(exc).__name__,
                "detail": str(exc),
                "path": str(request.url),
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
        # Fall back to old backend/ location if artifacts/ not yet populated
        if not model_path.exists():
            model_path = pathlib.Path(_PROJECT_ROOT) / "backend" / "model.pkl"
            vec_path   = pathlib.Path(_PROJECT_ROOT) / "backend" / "vectorizer.pkl"
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
        Backward-compatible endpoint for the existing React frontend.

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

        vec        = vectorizer.transform([req.email])
        pred       = model.predict(vec)[0]
        proba      = model.predict_proba(vec)[0]
        confidence = float(proba[1] if pred == 1 else proba[0])
        label      = "Safe Email" if pred == 0 else "Phishing Email"

        return {"prediction": label, "confidence": round(confidence, 4)}

    return app


# ---------------------------------------------------------------------------
# Module-level app instance (for uvicorn auto-reload: uvicorn api.app:app)
# ---------------------------------------------------------------------------
app = create_app()


# ---------------------------------------------------------------------------
# Programmatic launcher (called by main.py CLI)
# ---------------------------------------------------------------------------
def run(host: str = "0.0.0.0", port: int = 5000, reload: bool = False):
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
