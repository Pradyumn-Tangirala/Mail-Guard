"""
dashboard/__init__.py
======================
Public surface of the dashboard package.

The real implementation lives in dashboard/app.py (Streamlit).
This __init__.py provides a launcher callable so main.py can invoke
`python main.py dashboard` without knowing the Streamlit internals.
"""

import subprocess
import sys
import os


def launch_dashboard(host: str = "0.0.0.0", port: int = 8501):
    """
    Launch the Streamlit dashboard as a subprocess.

    Equivalent to running:
        streamlit run dashboard/app.py --server.address=<host> --server.port=<port>
    """
    app_path = os.path.join(os.path.dirname(__file__), "app.py")
    cmd = [
        sys.executable, "-m", "streamlit", "run", app_path,
        f"--server.address={host}",
        f"--server.port={port}",
        "--server.headless=true",
    ]
    subprocess.run(cmd, check=True)


def render_threat_feed(reports: list) -> None:
    """Stub — rendering is handled directly in dashboard/app.py session state."""
    pass


def render_statistics(reports: list) -> dict:
    """Stub — statistics are computed inline in dashboard/app.py."""
    return {}


__all__ = ["launch_dashboard", "render_threat_feed", "render_statistics"]
