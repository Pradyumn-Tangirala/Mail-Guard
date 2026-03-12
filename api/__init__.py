"""
api/__init__.py
================
Public surface of the api package.

The real implementation lives in api/app.py.
This __init__.py re-exports the factory and launcher so that main.py
can call `from api import create_app` without knowing the submodule name.
"""

from api.app import create_app, run, app

def health_check() -> dict:
    """Return API health status. Kept for backward compatibility with main.py."""
    from datetime import datetime, timezone
    return {
        "status": "ok",
        "version": "0.2.0",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

__all__ = ["create_app", "run", "app", "health_check"]
