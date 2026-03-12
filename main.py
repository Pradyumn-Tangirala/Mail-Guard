"""
main.py — MailGuard Pipeline Entry Point
=========================================
Connects all layers of the MailGuard threat detection pipeline:

  Raw Email
      │
      ▼
  preprocessing     ── parse, clean, extract NLP features
      │
      ├──► url_analysis      ── regex extraction, IP/shortener detection,
      │                          WHOIS domain-age check, per-URL scoring
      │
      ├──► header_analysis   ── SPF / DKIM / DMARC evaluation,
      │                          domain mismatch + spoofing detection
      │
      ├──► models            ── GradientBoosting NLP inference
      │
      ▼
  threat_scoring    ── weighted aggregation → ThreatLevel verdict + report
      │
      ├──► api              ── FastAPI REST server
      │
      └──► dashboard        ── real-time monitoring UI
"""

import logging
import argparse

# ── Layer imports ──────────────────────────────────────────────────────────────
from preprocessing import parse_raw_email, clean_text, extract_features

# url_analysis: use scan_body() for full structured scan in one call
from url_analysis import scan_body

# header_analysis: use header_threat_score() for weighted composite score,
# plus the individual check functions for detailed report fields
from header_analysis import (
    parse_headers,
    check_spf,
    check_dkim,
    check_dmarc,
    detect_spoofing,
    get_spoofing_flags,
    header_threat_score,
)

from models import load_model, run_inference
from threat_scoring import aggregate_scores, classify_threat, generate_report, ThreatLevel
from api import create_app, health_check
from dashboard import launch_dashboard

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
)
logger = logging.getLogger("mailguard")


# ── Core pipeline ──────────────────────────────────────────────────────────────

def run_pipeline(raw_email: str, email_id: str = "unknown") -> dict:
    """
    Execute the full MailGuard threat detection pipeline on a single raw email.

    Args:
        raw_email:  The complete raw email string (headers + body).
        email_id:   An identifier for this email (e.g. Message-ID or UUID).

    Returns:
        A threat report dict produced by threat_scoring.generate_report().
    """
    logger.info(f"[{email_id}] Starting pipeline analysis.")

    # ── Stage 1: Preprocessing ─────────────────────────────────────────────────
    logger.info(f"[{email_id}] Stage 1 — Preprocessing")
    parsed       = parse_raw_email(raw_email)
    clean_body   = clean_text(parsed.get("body", ""))
    nlp_features = extract_features(parsed)

    # ── Stage 2: URL Analysis ──────────────────────────────────────────────────
    # scan_body() returns a rich dict:
    #   urls_found, ip_based, shortened, newly_registered, blacklisted,
    #   url_scores {url: float}, max_score
    logger.info(f"[{email_id}] Stage 2 — URL Analysis")
    url_scan   = scan_body(clean_body)
    url_signal = url_scan["max_score"]

    if url_scan["ip_based"]:
        logger.warning(f"[{email_id}] IP-based URLs detected: {url_scan['ip_based']}")
    if url_scan["shortened"]:
        logger.warning(f"[{email_id}] Shortened URLs detected: {url_scan['shortened']}")
    if url_scan["newly_registered"]:
        logger.warning(f"[{email_id}] Newly registered domains: {url_scan['newly_registered']}")

    # ── Stage 3: Header Analysis ───────────────────────────────────────────────
    # parse_headers() accepts the full raw email string directly.
    # header_threat_score() gives a single weighted float (SPF 25%, DKIM 25%,
    # DMARC 30%, Spoofing 20%) so we don't need to assemble signals manually.
    logger.info(f"[{email_id}] Stage 3 — Header Analysis")
    headers       = parse_headers(raw_email)          # parse once, reuse below
    header_signal = header_threat_score(headers)

    # Collect detailed sub-results for the report
    spf_result     = check_spf(headers)
    dkim_result    = check_dkim(headers)
    dmarc_result   = check_dmarc(headers)
    spoof_flags    = get_spoofing_flags(headers)

    if spoof_flags:
        logger.warning(f"[{email_id}] Spoofing flags: {spoof_flags}")

    # ── Stage 4: ML Model Inference ────────────────────────────────────────────
    logger.info(f"[{email_id}] Stage 4 — Model Inference")
    model      = load_model("phishing_classifier_v1")
    nlp_result = run_inference(model, nlp_features)
    nlp_signal = nlp_result.get("threat_probability", 0.0)

    # ── Stage 5: Threat Scoring ────────────────────────────────────────────────
    logger.info(f"[{email_id}] Stage 5 — Threat Scoring")
    signals = {
        # Scalar signals consumed by aggregate_scores()
        "url_score":    url_signal,
        "header_score": header_signal,
        "nlp_score":    nlp_signal,
        # Detailed sub-results carried through to the report
        "spf":             spf_result,
        "dkim":            dkim_result,
        "dmarc":           dmarc_result,
        "spoofing_flags":  spoof_flags,
        "url_scan":        url_scan,
    }
    aggregate = aggregate_scores(signals)
    verdict   = classify_threat(aggregate)
    report    = generate_report(email_id, signals, verdict)

    logger.info(
        f"[{email_id}] Pipeline complete — "
        f"Score: {aggregate:.3f}  Verdict: {verdict.value}"
    )
    return report


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MailGuard — Layered Email Threat Detection Pipeline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Analyze a single email from stdin or file
    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze a raw email through the full pipeline."
    )
    analyze_parser.add_argument(
        "--email-file", "-f",
        type=str,
        help="Path to a raw .eml file. If omitted, reads from stdin.",
    )
    analyze_parser.add_argument(
        "--id", "-i",
        type=str,
        default="cli-email",
        help="Optional email identifier for logging.",
    )

    # Start the REST API server
    api_parser = subparsers.add_parser("api", help="Start the MailGuard REST API server.")
    api_parser.add_argument("--host", default="0.0.0.0")
    api_parser.add_argument("--port", type=int, default=5000)

    # Start the monitoring dashboard
    dash_parser = subparsers.add_parser("dashboard", help="Launch the real-time monitoring dashboard.")
    dash_parser.add_argument("--host", default="0.0.0.0")
    dash_parser.add_argument("--port", type=int, default=8050)

    args = parser.parse_args()

    if args.command == "analyze":
        if args.email_file:
            with open(args.email_file, "r", encoding="utf-8") as f:
                raw_email = f.read()
        else:
            import sys
            raw_email = sys.stdin.read()
        report = run_pipeline(raw_email, email_id=args.id)
        import json
        print(json.dumps(report, indent=2, default=str))

    elif args.command == "api":
        app = create_app()
        logger.info(f"Starting MailGuard API on {args.host}:{args.port}")
        app.run(host=args.host, port=args.port)

    elif args.command == "dashboard":
        logger.info(f"Launching MailGuard Dashboard on {args.host}:{args.port}")
        launch_dashboard(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
