"""
dashboard/app.py
=================
MailGuard Security Operations Dashboard — built with Streamlit.

Features
────────
  - Paste raw email text directly into the UI
  - Analyses via the FastAPI /analyze endpoint
  - Animated threat score gauge (SVG-based, no external JS)
  - Color-coded verdict banner (SAFE / SUSPICIOUS / PHISHING / MALWARE)
  - Triggered security rules table
  - Expandable signal drill-down (URL scan, header checks, NLP score)
  - Session-scoped verdict history table

Run with:
  streamlit run dashboard/app.py
Or via main.py CLI:
  python main.py dashboard
"""

import json
import sys
import os
import textwrap
from datetime import datetime

# ── Ensure project root is in sys.path for robust imports ─────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st  # type: ignore

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
API_BASE = os.getenv("MAILGUARD_API_URL", "http://localhost:5000")
ANALYZE_URL = f"{API_BASE}/analyze"
HEALTH_URL  = f"{API_BASE}/health"

# Verdict colour palette (border, background, text)
_VERDICT_STYLE = {
    "SAFE":       ("##2ECC71", "#0d2b1a", "#2ECC71"),
    "SUSPICIOUS": ("#F0A500", "#2b2000", "#F0A500"),
    "PHISHING":   ("#E07B00", "#2b1500", "#E07B00"),
    "MALWARE":    ("#E74C3C", "#2b0a08", "#E74C3C"),
}

_SAMPLE_EMAIL = textwrap.dedent("""\
    From: "PayPal Support" <billing@evil-domain.com>
    Return-Path: <noreply@phish.net>
    Reply-To: attacker@gmail.com
    Subject: Urgent: Verify your account immediately
    Authentication-Results: mx.google.com; spf=fail; dkim=fail
    Message-ID: <phish-20260312@phish.net>

    Dear Customer,

    We have detected suspicious login activity on your PayPal account.
    Please verify your identity immediately by clicking the link below:

    http://192.168.1.100/paypal/verify?token=abc123
    Alternatively use: https://bit.ly/3xYzPhish

    Failure to verify within 24 hours will result in account suspension.

    PayPal Security Team
""")


# ===========================================================================
# Page config  (must be first Streamlit call)
# ===========================================================================
st.set_page_config(
    page_title="MailGuard SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ===========================================================================
# Global CSS
# ===========================================================================
st.markdown("""
<style>
/* ── Background & typography ──────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0B1120;
    color: #C9D1E0;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}
[data-testid="stSidebar"] {
    background-color: #0E1628;
    border-right: 1px solid #1C2B45;
}

/* ── Header strip ─────────────────────────────────────────────────────────── */
.mg-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 24px;
    background: linear-gradient(135deg, #0E1628 0%, #112240 100%);
    border-radius: 12px;
    border: 1px solid #1C3A5E;
    margin-bottom: 28px;
}
.mg-header-logo { font-size: 2.4rem; }
.mg-header-title { font-size: 1.6rem; font-weight: 700; color: #E2E8F4; letter-spacing: 0.5px; }
.mg-header-sub   { font-size: 0.82rem; color: #637A9F; margin-top: 2px; }

/* ── Cards ────────────────────────────────────────────────────────────────── */
.mg-card {
    background: #0E1628;
    border: 1px solid #1C2B45;
    border-radius: 10px;
    padding: 20px 22px;
    margin-bottom: 16px;
}
.mg-card-title {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: #637A9F;
    margin-bottom: 10px;
}

/* ── Verdict banner ───────────────────────────────────────────────────────── */
.mg-verdict-banner {
    border-radius: 10px;
    border-left: 5px solid;
    padding: 16px 22px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.mg-verdict-label {
    font-size: 1.5rem;
    font-weight: 800;
    letter-spacing: 1.5px;
}
.mg-verdict-score {
    font-size: 0.9rem;
    opacity: 0.8;
    margin-top: 3px;
}

/* ── Rule table ───────────────────────────────────────────────────────────── */
.mg-rule-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 9px 0;
    border-bottom: 1px solid #1C2B45;
    font-size: 0.88rem;
}
.mg-rule-id {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.78rem;
    color: #E74C3C;
    background: #1e0e0e;
    border-radius: 4px;
    padding: 2px 7px;
    white-space: nowrap;
    min-width: 74px;
    text-align: center;
}
.mg-rule-id-hdr  { color: #F0A500; background: #231800; }
.mg-rule-id-nlp  { color: #5B9BD5; background: #0b1a2e; }
.mg-rule-id-crit { color: #E74C3C; background: #1e0808; border: 1px solid #E74C3C; }

/* ── Metric chips ─────────────────────────────────────────────────────────── */
.mg-metric {
    background: #112240;
    border: 1px solid #1C3A5E;
    border-radius: 8px;
    padding: 14px 18px;
    text-align: center;
}
.mg-metric-label { font-size: 0.7rem; color: #637A9F; text-transform: uppercase; letter-spacing: 1px; }
.mg-metric-value { font-size: 1.6rem; font-weight: 700; color: #C9D1E0; margin-top: 4px; }

/* ── Status dot ───────────────────────────────────────────────────────────── */
.mg-dot-green { color: #2ECC71; }
.mg-dot-red   { color: #E74C3C; }

/* ── Hide Streamlit chrome ────────────────────────────────────────────────── */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stTextArea"] textarea {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.82rem;
    background: #060D1A;
    color: #A8B4C8;
    border: 1px solid #1C2B45;
    border-radius: 8px;
}
[data-testid="stButton"] button {
    background: linear-gradient(135deg, #1565C0, #0D47A1);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 28px;
    font-weight: 600;
    font-size: 0.95rem;
    letter-spacing: 0.5px;
    transition: opacity 0.2s;
    width: 100%;
}
[data-testid="stButton"] button:hover { opacity: 0.88; }
</style>
""", unsafe_allow_html=True)


# ===========================================================================
# Helpers
# ===========================================================================

def _call_api(raw_email: str) -> dict:
    """POST raw email to the FastAPI /analyze endpoint. Returns report dict."""
    try:
        import httpx  # type: ignore
        resp = httpx.post(
            ANALYZE_URL,
            json={"email": raw_email, "email_id": "dashboard-session"},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except ImportError:
        st.error("httpx is not installed. Run: `pip install httpx`")
        st.stop()
        return {} # Satisfy IDE return path check
    except Exception as exc:
        st.error(f"API call failed: {exc}")
        return {}


def _api_online() -> bool:
    try:
        import httpx  # type: ignore
        r = httpx.get(HEALTH_URL, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _gauge_svg(score: int, color: str) -> str:
    """
    Render an SVG arc gauge (0–100) with no external dependencies.
    arc goes from 225° to -45° (270° sweep).
    """
    import math
    pct      = score / 100
    cx, cy   = 100, 95
    r        = 72
    sweep    = 270
    start_a  = 225
    end_a    = start_a - sweep * pct
    rad_s    = math.radians(start_a)
    rad_e    = math.radians(end_a)
    x1, y1   = cx + r * math.cos(rad_s), cy - r * math.sin(rad_s)
    x2, y2   = cx + r * math.cos(rad_e), cy - r * math.sin(rad_e)
    large    = 1 if sweep * pct > 180 else 0

    return f"""
    <svg viewBox="0 0 200 160" xmlns="http://www.w3.org/2000/svg" style="max-width:220px;margin:auto;display:block">
      <!-- Track -->
      <path d="M {cx + r * math.cos(math.radians(225)):.1f} {cy - r * math.sin(math.radians(225)):.1f}
               A {r} {r} 0 1 1 {cx + r * math.cos(math.radians(-45)):.1f} {cy - r * math.sin(math.radians(-45)):.1f}"
            fill="none" stroke="#1C2B45" stroke-width="12" stroke-linecap="round"/>
      <!-- Value arc -->
      <path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 {large} 0 {x2:.1f} {y2:.1f}"
            fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"
            style="filter:drop-shadow(0 0 6px {color})"/>
      <!-- Score text -->
      <text x="{cx}" y="{cy + 6}" text-anchor="middle"
            font-size="30" font-weight="700" fill="{color}"
            font-family="Inter,sans-serif">{score}</text>
      <text x="{cx}" y="{cy + 24}" text-anchor="middle"
            font-size="10" fill="#637A9F" font-family="Inter,sans-serif">THREAT SCORE</text>
    </svg>
    """


def _rule_category_class(rule_id: str) -> str:
    if rule_id.startswith("URL"):  return "mg-rule-id"
    if rule_id.startswith("HDR"):  return "mg-rule-id mg-rule-id-hdr"
    if rule_id.startswith("NLP"):  return "mg-rule-id mg-rule-id-nlp"
    return "mg-rule-id mg-rule-id-crit"


def _bool_badge(val: bool) -> str:
    return (
        '<span style="color:#2ECC71;font-weight:700">PASS</span>' if val
        else '<span style="color:#E74C3C;font-weight:700">FAIL</span>'
    )


# ===========================================================================
# Sidebar
# ===========================================================================

with st.sidebar:
    st.markdown("## 🛡️ MailGuard")
    st.markdown("---")

    api_ok = _api_online()
    dot    = "🟢" if api_ok else "🔴"
    status_text = "Connected" if api_ok else "Offline"
    st.markdown(f"**API Status:** {dot} {status_text}")
    st.markdown(f"**Endpoint:** `{API_BASE}`")
    st.markdown("---")

    st.markdown("#### Scoring Weights")
    st.markdown("""
| Layer | Weight |
|---|---|
| NLP (ML Model) | 40% |
| URL Analysis | 35% |
| Header Analysis | 25% |
""")

    st.markdown("---")
    st.markdown("#### Classification")
    st.markdown("""
| Score | Label |
|---|---|
| 0–29 | 🟢 SAFE |
| 30–54 | 🟡 SUSPICIOUS |
| 55–79 | 🟠 PHISHING |
| 80–100 | 🔴 MALWARE |
""")
    st.markdown("---")
    st.caption("MailGuard v0.2.0 · SOC Pipeline")


# ===========================================================================
# Main content
# ===========================================================================

st.markdown("""
<div class="mg-header">
  <div class="mg-header-logo">🛡️</div>
  <div>
    <div class="mg-header-title">MailGuard — Threat Detection Dashboard</div>
    <div class="mg-header-sub">SOC-grade email analysis · Header · URL · NLP · SIEM-ready output</div>
  </div>
</div>
""", unsafe_allow_html=True)

# Session history state
if "history" not in st.session_state:
    st.session_state.history = []

# ── Input panel ────────────────────────────────────────────────────────────────
col_input, col_results = st.columns([1, 1], gap="large")

with col_input:
    st.markdown('<div class="mg-card-title">📧 Raw Email Input</div>', unsafe_allow_html=True)

    sample_btn = st.button("Load sample phishing email", key="sample")
    if sample_btn:
        st.session_state["email_input"] = _SAMPLE_EMAIL

    raw_email = st.text_area(
        label="Paste raw .eml content (headers + body)",
        value=st.session_state.get("email_input", ""),
        height=340,
        key="email_box",
        label_visibility="collapsed",
        placeholder="Paste raw email here (including From:, Subject:, headers and body)...",
    )

    analyze_btn = st.button("🔍 Analyze Email", key="analyze", use_container_width=True)

# ── Analysis logic ─────────────────────────────────────────────────────────────
report = None
if analyze_btn:
    if not raw_email.strip():
        with col_results:
            st.warning("Paste an email before analyzing.")
    elif not api_ok:
        with col_results:
            st.error(
                f"MailGuard API is not reachable at **{API_BASE}**.\n\n"
                "Start it with:\n```\npython main.py api --port 5000\n```"
            )
    else:
        with st.spinner("Analyzing…"):
            report = _call_api(raw_email)

        if report:
            mg = report.get("mailguard", {})
            # Store in history
            st.session_state.history.append({
                "time":       datetime.now().strftime("%H:%M:%S"),
                "email_id":   mg.get("email_id", "—"),
                "score":      mg.get("threat_score", 0),
                "verdict":    mg.get("classification", "—"),
                "rules_hit":  mg.get("triggered_rule_count", 0),
            })

# ── Results panel ──────────────────────────────────────────────────────────────
with col_results:
    if report:
        mg      = report.get("mailguard", {})
        evt     = report.get("event", {})
        score   = mg.get("threat_score", 0)
        verdict = mg.get("classification", "SAFE")
        rules   = mg.get("triggered_rules", [])
        signals = mg.get("signals", {})
        details = mg.get("details", {})

        border_c, bg_c, text_c = _VERDICT_STYLE.get(verdict, ("#637A9F", "#111827", "#C9D1E0"))

        # Verdict banner
        st.markdown(f"""
        <div class="mg-verdict-banner" style="border-color:{border_c};background:{bg_c};">
          <div>
            <div class="mg-verdict-label" style="color:{text_c}">{verdict}</div>
            <div class="mg-verdict-score" style="color:{border_c}">
              Risk Score: {score}/100 · Severity: {evt.get('severity','—')}/4 ·
              {len(rules)} rule{'s' if len(rules)!=1 else ''} triggered
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Gauge + signal metrics
        g_col, m_col = st.columns([1, 1])
        with g_col:
            st.markdown(_gauge_svg(score, text_c), unsafe_allow_html=True)
        with m_col:
            st.markdown(f"""
            <div style="display:flex;flex-direction:column;gap:8px;padding-top:10px;">
              <div class="mg-metric">
                <div class="mg-metric-label">NLP Score</div>
                <div class="mg-metric-value">{signals.get('nlp_score',0)*100:.0f}%</div>
              </div>
              <div class="mg-metric">
                <div class="mg-metric-label">URL Score</div>
                <div class="mg-metric-value">{signals.get('url_score',0)*100:.0f}%</div>
              </div>
              <div class="mg-metric">
                <div class="mg-metric-label">Header Score</div>
                <div class="mg-metric-value">{signals.get('header_score',0)*100:.0f}%</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # ── Triggered rules ────────────────────────────────────────────────────
        if rules:
            st.markdown('<div class="mg-card-title">⚠️ Triggered Security Rules</div>', unsafe_allow_html=True)
            rows_html = ""
            for r in rules:
                rid   = r["rule_id"]
                cls   = _rule_category_class(rid)
                rows_html += f"""
                <div class="mg-rule-row">
                  <span class="{cls}">{rid}</span>
                  <span>{r['description']}</span>
                </div>"""
            st.markdown(rows_html, unsafe_allow_html=True)
            st.markdown("")

        # ── Detail expanders ───────────────────────────────────────────────────
        hdr = details.get("header", {})
        url = details.get("url", {})
        nlp = details.get("nlp", {})

        with st.expander("🔐 Header Authentication Details"):
            h_cols = st.columns(3)
            spf   = hdr.get("spf",  {})
            dkim  = hdr.get("dkim", {})
            dmarc = hdr.get("dmarc",{})
            st.markdown(f"""
            | Check | Result | Details |
            |---|---|---|
            | SPF  | {_bool_badge(spf.get('passed',False))} | `{spf.get('raw','—')}` |
            | DKIM | {_bool_badge(dkim.get('passed',False))} | `{dkim.get('raw','—')}` |
            | DMARC Alignment | {_bool_badge(dmarc.get('aligned',False))} | `{dmarc.get('from_domain','?')}` vs `{dmarc.get('return_path_domain','?')}` |
            """, unsafe_allow_html=True)
            spoofs = hdr.get("spoofing_flags", [])
            if spoofs:
                st.markdown("**Spoofing Flags:**")
                for f in spoofs:
                    st.markdown(f"- 🚩 `{f}`")

        with st.expander(f"🔗 URL Analysis ({url.get('total_urls',0)} URLs found)"):
            if url.get("ip_based"):
                st.error(f"**IP-based URLs:** {url['ip_based']}")
            if url.get("shortened"):
                st.warning(f"**Shortened URLs:** {url['shortened']}")
            if url.get("newly_registered"):
                st.warning(f"**Newly Registered Domains:** {url['newly_registered']}")
            if url.get("blacklisted"):
                st.error(f"**Blacklisted URLs:** {url['blacklisted']}")
            per_url = url.get("per_url_scores", {})
            if per_url:
                st.markdown("**Per-URL Scores:**")
                for u, s in per_url.items():
                    bar = int(s * 20)
                    st.markdown(f"- `{u[:60]}` — **{s:.2f}** {'█' * bar}{'░' * (20-bar)}")

        with st.expander("🤖 ML Model Output"):
            st.markdown(f"""
            | Property | Value |
            |---|---|
            | Model | `{nlp.get('model','—')}` |
            | Label | `{nlp.get('label','—')}` |
            | Probability | **{nlp.get('probability',0)*100:.1f}%** |
            """)

        with st.expander("📋 Raw SIEM JSON"):
            st.code(json.dumps(report, indent=2, default=str), language="json")

    else:
        st.markdown("""
        <div style="padding:40px;text-align:center;color:#637A9F;border:1px dashed #1C2B45;border-radius:10px;margin-top:10px">
          <div style="font-size:2.5rem;margin-bottom:12px">🛡️</div>
          <div style="font-size:1rem;font-weight:600">Paste an email and click Analyze</div>
          <div style="font-size:0.82rem;margin-top:8px">
            Results will appear here — score gauge, triggered rules, and full SIEM JSON
          </div>
        </div>
        """, unsafe_allow_html=True)


# ===========================================================================
# Session history
# ===========================================================================
if st.session_state.history:
    st.markdown("---")
    st.markdown('<div class="mg-card-title">📊 Session Analysis History</div>', unsafe_allow_html=True)

    import pandas as pd  # type: ignore
    df = pd.DataFrame(st.session_state.history)
    df.columns = ["Time", "Email ID", "Threat Score", "Verdict", "Rules Hit"]

    def _style_verdict(v):
        colors = {
            "SAFE": "color:#2ECC71",
            "SUSPICIOUS": "color:#F0A500",
            "PHISHING": "color:#E07B00",
            "MALWARE": "color:#E74C3C",
        }
        return colors.get(v, "")

    st.dataframe(
        df.style.applymap(_style_verdict, subset=["Verdict"])
               .background_gradient(subset=["Threat Score"], cmap="RdYlGn_r"),
        use_container_width=True,
        hide_index=True,
    )
