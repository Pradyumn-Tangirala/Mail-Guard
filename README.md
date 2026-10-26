<div align="center">

# 🛡️ MailGuard

### Multi-Layer Email Phishing Detection Prototype

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.55-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Prototype-lightgrey?style=flat-square)](#project-status)

*Combines email-header checks, URL heuristics and a text classifier into one weighted threat score, with rule-level explanations and ECS-style JSON output.*

</div>

## Project Status

MailGuard is a **learning / portfolio prototype**, not a production mail filter. The pipeline runs end to end and every layer produces a real signal, but:

- The ML classifier is trained on a **real public dataset** (3,012 emails) with a documented, reproducible evaluation. The training corpora are old and narrow, though, and it generalises poorly to attack types it has not seen (see [Dataset & Model Evaluation](#dataset--model-evaluation)).
- Threat-intelligence blacklist lookup and redirect resolution are **stubs**.
- SPF / DKIM results are **read from headers added by the receiving mail server**; MailGuard does not perform DNS or cryptographic verification itself.

The [Feature Status](#feature-status) table lists exactly what is implemented, partial, or stubbed. Planned work is in the [Roadmap](#roadmap).

### Recent changes (2026-10-25)

- **Repository hygiene:** untracked the committed `.env` (replaced by `.env.example`) and all `__pycache__/*.pyc` files. Removed the unused `data/email.csv` (an empty Excel workbook with a `.csv` name) and `data/email_fixed.csv` (the old 10-row toy training set).
- **Legacy model removed:** deleted `backend/` (an old server plus a model of unknown provenance). `/predict` now loads only `models/artifacts/`.
- **URL parsing fixes:** hosts are read with `urlparse().hostname`. This fixes an `lstrip("www.")` bug that turned `web.com` into `eb.com`, detects the userinfo trick (`http://paypal.com@1.2.3.4/` is now IP-based), and handles IPv6 hosts.
- **Links hidden in HTML:** URLs are extracted from the raw body, so links that exist only inside `<a href>` are now scanned. The NLP model's input is unchanged.
- **DMARC alignment:** a DKIM pass now counts towards DMARC only if the signing domain (`d=`) aligns with the From domain.
- **API hardening:** 1,000,000-character input limit (422), a generic 500 response with a request id (details are logged server-side only), and a CORS allow-list from `MAILGUARD_CORS_ORIGINS` with credentials disabled.
- **No retraining:** none of these changes touch the classifier's input, so the model and every number in [Dataset & Model Evaluation](#dataset--model-evaluation) are unchanged.

## Overview

MailGuard takes a raw email (`.eml` text) and runs it through three independent analysis layers:

1. **Header analysis**: authentication results, envelope/domain mismatches, display-name brand impersonation
2. **URL analysis**: IP-host URLs, known URL shorteners, domain age via WHOIS
3. **NLP classifier**: TF-IDF + Logistic Regression on the email body, trained on the public Nazario_5 corpus

The layer scores are combined into a weighted 0–100 threat score, a 14-rule engine adds human-readable explanations, and the result is emitted as JSON whose layout loosely follows the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html). It can be used from a CLI, a FastAPI REST API, or a Streamlit dashboard.

## Pipeline Architecture

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                     RAW EMAIL INPUT (.eml text)                 │
  └───────────────────────────┬─────────────────────────────────────┘
                              │
                              ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  STAGE 1 · PREPROCESSING                preprocessing/          │
  │──────────────────────────────────────────────────────────────── │
  │  parse_raw_email()  →  clean_text()  →  extract_features()      │
  │  stdlib email parser · HTML tag stripping · whitespace cleanup  │
  └──────┬──────────────────────┬──────────────────────────────────┘
         │                      │
         ▼                      ▼
  ┌─────────────────┐   ┌──────────────────────────────────────────┐
  │  STAGE 2        │   │  STAGE 3                                 │
  │  URL ANALYSIS   │   │  HEADER ANALYSIS                         │
  │  url_analysis/  │   │  header_analysis/                        │
  │─────────────────│   │──────────────────────────────────────────│
  │ • Regex extract │   │ • SPF result read from headers           │
  │ • IP-host URLs  │   │ • DKIM result read from headers          │
  │ • Shorteners    │   │ • From / Return-Path alignment           │
  │ • WHOIS domain  │   │   (local DMARC approximation)            │
  │   age (<30 days)│   │ • Reply-To mismatch                      │
  │ • Blacklist     │   │ • Display-name brand impersonation       │
  │   (stub)        │   │ • Composite header score                 │
  │ • Redirects     │   │                                          │
  │   (stub)        │   │                                          │
  └────────┬────────┘   └─────────────────────┬────────────────────┘
           │                                   │
           └──────────────┬────────────────────┘
                          │
                          ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  STAGE 4 · ML MODEL INFERENCE                      models/      │
  │──────────────────────────────────────────────────────────────── │
  │  TF-IDF + LogisticRegression (Nazario_5, 3k real emails)        │
  │  load_model()  →  run_inference()  →  threat_probability float  │
  └───────────────────────────┬─────────────────────────────────────┘
                              │
                              ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  STAGE 5 · THREAT SCORING ENGINE            threat_scoring/     │
  │──────────────────────────────────────────────────────────────── │
  │                                                                 │
  │  Score = NLP×0.40 + URL×0.35 + Header×0.25  →  0-100            │
  │                                                                 │
  │  ┌──────────┬─────────────┬───────────┬──────────────────────┐  │
  │  │  0 – 29  │   30 – 54   │  55 – 79  │      80 – 100        │  │
  │  │  🟢 SAFE │🟡 SUSPICIOUS│🟠 PHISHING│ 🔴 MALWARE (see note)│  │
  │  └──────────┴─────────────┴───────────┴──────────────────────┘  │
  │                                                                 │
  │  14-rule engine (URL / HDR / NLP / CRIT)                        │
  │  generate_report()  →  ECS-style JSON                           │
  └──────────┬───────────────────────────────────────┬─────────────┘
             │                                       │
             ▼                                       ▼
  ┌──────────────────────┐             ┌─────────────────────────┐
  │  FastAPI REST API    │             │  Streamlit Dashboard    │
  │  api/app.py          │             │  dashboard/app.py       │
  │──────────────────────│             │─────────────────────────│
  │  POST /analyze       │             │  Paste-and-analyze UI   │
  │  POST /predict       │             │  Threat score gauge     │
  │  GET  /health        │             │  Triggered rule table   │
  │  GET  /version       │             │  Header / URL / ML views│
  │  OpenAPI /docs       │             │  Raw JSON viewer        │
  └──────────────────────┘             └─────────────────────────┘
```

## Feature Status

| Capability | Status | Notes |
|---|---|---|
| Raw `.eml` parsing | ✅ Implemented | Python stdlib `email`; text/plain and text/html parts |
| SPF / DKIM result evaluation | ⚠️ Partial | Parses `Authentication-Results` / `Received-SPF` written by the receiving MTA. **No DNS SPF lookup and no DKIM signature verification.** A bare `DKIM-Signature` header is reported as `present_unverified` |
| DMARC check | ⚠️ Partial | Local identifier-alignment check: SPF pass with an aligned Return-Path, **or** DKIM pass with an aligned signing domain (`d=`). Relaxed alignment means same domain or subdomain (no Public Suffix List). **No `_dmarc` DNS policy lookup.** A missing Return-Path counts as SPF-misaligned |
| From / Return-Path mismatch | ✅ Implemented | |
| Reply-To mismatch | ✅ Implemented | |
| Display-name brand impersonation | ⚠️ Partial | Substring match against a fixed list of 14 brand keywords; prone to false positives (e.g. `"ups"` matches "Startups") |
| IP-host URL detection | ✅ Implemented | IPv4 and IPv6, via the parsed hostname, so `user@host` userinfo tricks are caught |
| URL shortener detection | ✅ Implemented | Fixed list of 25 shortener domains |
| Domain age (WHOIS) | ⚠️ Partial | Live WHOIS lookups (3 s timeout, in-process cache); fails open when offline or when WHOIS returns no date |
| URL extraction from HTML emails | ✅ Implemented | URLs are extracted from the raw body, including `href` attributes |
| Threat-intel blacklist (URL-004, CRIT-002) | 🚧 Stub | `check_blacklist()` always returns `False`; these rules cannot currently fire |
| Redirect resolution | 🚧 Stub | `resolve_redirects()` returns the URL unchanged |
| Attachment / malware analysis | ❌ Not implemented | `has_attachments` is a hardcoded placeholder |
| NLP classifier | ✅ Implemented | TF-IDF + Logistic Regression trained on 2,409 real emails; test F1 0.98. Weak on unseen attack types (see [Evaluation](#dataset--model-evaluation)) |
| Weighted score + 4 classification bands | ✅ Implemented | |
| 14-rule explanation engine | ✅ Implemented | 12 of 14 rules can fire today |
| ECS-style JSON report | ✅ Implemented | Loosely ECS-aligned; see [notes](#ecs-notes) |
| FastAPI REST API | ✅ Implemented | No authentication or rate limiting. Input size limit, generic 500 responses, CORS allow-list |
| Streamlit dashboard | ✅ Implemented | Analyses on demand; history is per browser session only |
| CLI (`main.py analyze`) | ✅ Implemented | |
| Tests | ⚠️ Partial | 26 tests: smoke, model / text normalisation, URL parsing, DMARC alignment, HTML link scanning, API limits / errors / CORS. The rule engine and WHOIS paths have little coverage |

## Dataset & Model Evaluation

### Dataset

[**Phishing Email Curated Datasets**](https://zenodo.org/records/8339691), A. I. Champa et al., Zenodo, DOI [10.5281/zenodo.8339691](https://doi.org/10.5281/zenodo.8339691), licensed CC BY 4.0. It was released alongside two peer-reviewed 2024 papers (ISDFS 2024, ICMI 2024).

| File | Role | Emails used | Phishing / fraud | Legitimate |
|---|---|---|---|---|
| `Nazario_5.csv` | Train (80%) + test (20%) | 3,012 (3,065 raw, after cleaning / de-duplication) | 1,518 (Nazario phishing corpus, 2015–2022) | 1,494 (Enron, SpamAssassin, CEAS, TREC, Ling; 1992–2008) |
| `Nigerian_5.csv` | Unseen cross-dataset test | 4,758 (after removing 1,464 emails also present in Nazario_5) | 3,235 (advance-fee fraud) | 1,523 |

The data is **not committed**. `scripts/download_data.py` fetches both files from Zenodo and verifies their MD5 checksums. Columns available: sender, receiver, date, subject, body, label. There are **no authentication headers or Return-Path**, so this benchmark evaluates the **NLP layer only**; the header and URL layers are not benchmarked here.

### Protocol

1. Text = `normalize_for_model(clean_text(body))`, the exact function the live pipeline uses at inference (see *Leakage findings*).
2. Stratified 80/20 train/test split (`random_state=42`).
3. Two candidates share the same TF-IDF features (1–2-grams, 20k features): **Logistic Regression** (baseline) and **Gradient Boosting** (the previous model type).
4. The winner is chosen on **5-fold cross-validated F1 on the training split only**; the test split is used once, for reporting.
5. The winner is then tested on `Nigerian_5` to measure generalisation to an attack type it never saw.

### Results

| Model | CV F1 (train, 5-fold) | Test precision | Test recall | Test F1 | False-positive rate | ROC-AUC |
|---|---|---|---|---|---|---|
| **Logistic Regression** (shipped) | **0.983 ± 0.005** | **0.993** | **0.970** | **0.982** | **0.67%** | **0.999** |
| Gradient Boosting | 0.945 ± 0.011 | 0.972 | 0.914 | 0.942 | 2.68% | 0.990 |

Logistic Regression test confusion matrix (603 emails): **297** true negatives, **2** false positives, **9** false negatives, **295** true positives.

**Cross-dataset (Nigerian advance-fee fraud, never seen in training):**

| Precision | Recall | F1 | False-positive rate | ROC-AUC |
|---|---|---|---|---|
| 0.988 | **0.373** | 0.541 | 0.98% | 0.962 |

The model still *ranks* fraud above legitimate mail well (AUC 0.96), but at the default 0.5 threshold it **misses 63% of advance-fee fraud**. Those are long, story-driven letters, unlike the short credential-harvesting lures it was trained on. The in-distribution F1 of 0.98 therefore overstates how well it would do on real-world mail.

### Leakage findings

Inspecting the data and the model's top features exposed several shortcuts the model could take instead of learning phishing behaviour. Each one is handled in `preprocessing.normalize_for_model()` or `train_model.py`:

| Issue | Evidence | Mitigation |
|---|---|---|
| **Single-inbox artefact**: the Nazario corpus was collected in one mailbox | `jose` appears in 40% of phishing bodies and `monkey.org` in 38%, versus ~0% of legitimate ones | Tokens removed |
| **Era bias**: legitimate mail is from 1992–2008, phishing from 2015–2022 | In an earlier run, the years `2001`, `2007`, `2008` and `2022` were among the top-15 features | Years masked as `yeartoken` |
| **Masking residue** | Removing only `monkey` left `org` as a top phishing feature | `monkey.org` removed as a whole |
| **Hosts and addresses** | Specific domains and addresses are memorisable | Replaced by `urltoken` / `emailtoken` (the URL and header layers analyse them separately) |
| **Shared rows across files** | 1,464 legitimate emails appear in both `Nazario_5` and `Nigerian_5` | Removed from the cross-dataset test |

Masking barely moves the headline number (CV F1 0.984 unmasked vs 0.983 masked), but it changes **what the model relies on**. Top features after masking:

- **Phishing:** account, click, dear, email, update, verify, security, view, payment, mailbox, kindly, messages, upgrade, link
- **Legitimate:** list, wrote, like, plan, just, subject, july, know, mailing list, time, original, unsubscribe

The legitimate side is still dominated by early-2000s **mailing-list and reply-thread** language ("wrote", "mailing list", "original"). Modern legitimate mail, such as transactional email or marketing newsletters, is under-represented and more likely to be misjudged.

Reproduce every number above with `python scripts/download_data.py` and `python train_model.py`. All metrics are written to [`models/artifacts/metrics.json`](models/artifacts/metrics.json).

## Directory Structure

```
Mail-Guard/
│
├── main.py                     ← Pipeline (run_pipeline) + CLI entry point
├── train_model.py              ← Trains + benchmarks the NLP model, writes metrics.json
├── requirements.txt            ← Runtime dependencies
├── requirements-dev.txt        ← + test dependencies (pytest)
├── .env.example                ← Optional editor env (copy to .env)
├── pyrightconfig.json
├── LICENSE
│
├── preprocessing/__init__.py   ← Email parsing, HTML stripping, feature extraction
├── url_analysis/scanner.py     ← URL extraction, scoring, WHOIS checks
├── header_analysis/analyzer.py ← SPF/DKIM result parsing, alignment, spoofing flags
├── models/
│   ├── __init__.py             ← Model loading + inference
│   └── artifacts/              ← Committed model.pkl, vectorizer.pkl, metrics.json
├── threat_scoring/engine.py    ← Weighted aggregation, rule engine, JSON report
├── api/app.py                  ← FastAPI application
├── dashboard/app.py            ← Streamlit dashboard
│
├── samples/                    ← 6 synthetic .eml files + observed results (samples/README.md)
├── scripts/download_data.py    ← Downloads + MD5-verifies the Zenodo datasets
├── data/raw/                   ← Downloaded datasets (git-ignored)
├── tests/                      ← smoke, model, URL, header, pipeline and API tests
└── frontend/index.html         ← Original single-page HTML UI; calls POST /predict on port 8000
```

## Quick Start

Tested on Python 3.14. Python 3.11+ is required because the committed model artifacts were pickled with scikit-learn 1.8.0.

### 1. Install

```bash
git clone https://github.com/Pradyumn-Tangirala/Mail-Guard.git
cd Mail-Guard
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt   # or requirements.txt if you don't need the tests
```

Trained model artifacts are committed in `models/artifacts/`, so no training step is needed to run the pipeline.

### 2. Run the tests

```bash
python -m pytest tests
```

### 3. Analyze an email from the command line

```bash
python main.py analyze --email-file samples/test.eml --id test-001
python main.py analyze --email-file samples/phishing.eml --id phish-001
```

See [samples/README.md](samples/README.md) for what each sample contains and the verdict MailGuard currently gives it. The current model flags all 4 malicious samples and passes both benign ones. That's 6 hand-written emails, not a benchmark; the real metrics are in [Dataset & Model Evaluation](#dataset--model-evaluation).

The JSON report is printed to stdout; pipeline logs go to stderr. Emails with non-IP links trigger live WHOIS lookups, so the first run can take a few seconds (or fall back silently if you are offline).

Reading from stdin also works:

```bash
python main.py analyze --id eml-002 < samples/phishing.eml
# PowerShell: Get-Content samples/phishing.eml -Raw | python main.py analyze --id eml-002
```

### 4. Start the API server

```bash
python main.py api                # http://localhost:8000
# or, with auto-reload for development:
uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

Interactive API docs: **http://localhost:8000/docs**

### 5. Launch the dashboard

The dashboard calls the API, so start the API first (step 4).

```bash
python main.py dashboard          # http://localhost:8050
# or directly:
streamlit run dashboard/app.py    # http://localhost:8501
```

If the API is not on `http://localhost:8000`, set `MAILGUARD_API_URL` before launching the dashboard.

### 6. Call the API directly

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email": "From: attacker@phish.net\r\nSubject: Urgent\r\n\r\nClick here: http://1.2.3.4/login", "email_id": "test-001"}'
```

### (Optional) Retrain and re-evaluate the model

```bash
python scripts/download_data.py   # ~30 MB from Zenodo, MD5-verified, saved to data/raw/
python train_model.py             # ~1 minute
```

Training cross-validates both candidate models, prints the metrics, and **overwrites** `models/artifacts/model.pkl`, `vectorizer.pkl` and `metrics.json`.

## Detection Rules

| Rule ID | Category | Fires when | Status |
|---|---|---|---|
| `URL-001` | URL | A URL uses a bare IPv4 address as its host | ✅ Active |
| `URL-002` | URL | A URL uses a known shortener domain | ✅ Active |
| `URL-003` | URL | WHOIS reports a URL domain registered < 30 days ago | ⚠️ Needs network |
| `URL-004` | URL | A URL is on a threat-intel blacklist | 🚧 Inactive (stub) |
| `URL-005` | URL | Highest per-URL score ≥ 0.70 | ✅ Active |
| `HDR-001` | Header | SPF result is anything other than `pass` (including missing) | ✅ Active |
| `HDR-002` | Header | DKIM result is anything other than `pass` (including missing / unverified) | ✅ Active |
| `HDR-003` | Header | From-domain and Return-Path-domain are not aligned (or Return-Path is missing) | ✅ Active |
| `HDR-004` | Header | Any spoofing flag (envelope mismatch, Reply-To mismatch, brand impersonation) | ✅ Active |
| `HDR-005` | Header | Composite header score ≥ 0.60 | ✅ Active |
| `NLP-001` | NLP | Classifier phishing probability ≥ 0.80 | ✅ Active |
| `NLP-002` | NLP | Classifier phishing probability 0.50 – 0.79 | ✅ Active |
| `CRIT-001` | Composite | NLP ≥ 0.50 **and** URL ≥ 0.30 **and** Header ≥ 0.30 | ✅ Active |
| `CRIT-002` | Composite | Blacklisted URL **and** spoofing indicators | 🚧 Inactive (depends on URL-004) |

Rules only explain the verdict; they never change the numeric score. New rules can be added to `_RULES` in `threat_scoring/engine.py` without touching the weights.

Because HDR-001/002/003 treat *missing* authentication results as failures, emails that lack an `Authentication-Results` header (e.g. hand-written test emails) will usually trigger them even when legitimate.

## Scoring

| Layer | Weight | Layer score |
|---|---|---|
| NLP | 40% | Classifier phishing probability |
| URL | 35% | Highest per-URL score (IP host +0.55, shortener +0.30, new domain +0.40, capped at 1.0) |
| Header | 25% | SPF 25% + DKIM 25% + DMARC-approximation 30% + spoofing 20% |

| Score | Classification | ECS `event.severity` |
|---|---|---|
| 0 – 29 | `SAFE` | 1 |
| 30 – 54 | `SUSPICIOUS` | 2 |
| 55 – 79 | `PHISHING` | 3 |
| 80 – 100 | `MALWARE` | 4 |

> **Note on `MALWARE`:** this is only the name of the highest score band. MailGuard does not inspect attachments or detect malware. A credential-phishing email that scores 80+ (like `samples/phishing.eml`) is labelled `MALWARE`. Renaming this band is on the [Roadmap](#roadmap).

## JSON Output Format

Real output of `python main.py analyze --email-file samples/phishing.eml --id msg-phish-001` (timestamps will differ):

```json
{
  "@timestamp": "2026-10-03T17:40:15.585269+00:00",
  "event": {
    "created": "2026-10-03T17:40:15.585269+00:00",
    "kind": "alert",
    "category": ["email", "threat"],
    "type": ["indicator"],
    "severity": 4,
    "risk_score": 80,
    "dataset": "mailguard.threat",
    "provider": "mailguard",
    "action": "malware"
  },
  "mailguard": {
    "email_id": "msg-phish-001",
    "threat_score": 80,
    "classification": "MALWARE",
    "color": "red",
    "triggered_rules": [
      { "rule_id": "URL-001", "description": "IP-based URL detected: ['http://192.168.1.100/paypal/verify?token=abc123']" },
      { "rule_id": "URL-002", "description": "URL shortener detected: ['https://bit.ly/3xYzPhish']" },
      { "rule_id": "HDR-001", "description": "SPF authentication failure: spf=fail" },
      { "rule_id": "HDR-002", "description": "DKIM signature failure: dkim=fail" },
      { "rule_id": "HDR-003", "description": "DMARC alignment failure — From/Return-Path mismatch: evil-domain.com vs phish.net" },
      { "rule_id": "HDR-004", "description": "Spoofing indicator: ['from_return_path_mismatch:evil-domain.com vs phish.net', 'reply_to_hijack:evil-domain.com vs gmail.com', 'display_name_impersonation:paypal']" },
      { "rule_id": "HDR-005", "description": "High composite header threat score (>=0.60): score=0.89" },
      { "rule_id": "NLP-001", "description": "ML model high-confidence phishing prediction (>=0.80): probability=0.952" },
      { "rule_id": "CRIT-001", "description": "CRITICAL: All three layers triggered simultaneously (NLP + URL + Header)" }
    ],
    "triggered_rule_count": 9,
    "signals": {
      "nlp_score": 0.9524,
      "url_score": 0.55,
      "header_score": 0.89,
      "normalized": 0.795951
    },
    "details": {
      "header": {
        "spf":  { "raw": "spf=fail",  "passed": false, "score": 1.0 },
        "dkim": { "raw": "dkim=fail", "passed": false, "score": 0.8 },
        "dmarc": {
          "passed": false,
          "aligned": false,
          "dkim_aligned": false,
          "from_domain": "evil-domain.com",
          "return_path_domain": "phish.net",
          "dkim_domain": "",
          "score": 0.8
        },
        "spoofing_flags": [
          "from_return_path_mismatch:evil-domain.com vs phish.net",
          "reply_to_hijack:evil-domain.com vs gmail.com",
          "display_name_impersonation:paypal"
        ]
      },
      "url": {
        "total_urls": 2,
        "ip_based": ["http://192.168.1.100/paypal/verify?token=abc123"],
        "shortened": ["https://bit.ly/3xYzPhish"],
        "newly_registered": [],
        "blacklisted": [],
        "per_url_scores": {
          "http://192.168.1.100/paypal/verify?token=abc123": 0.55,
          "https://bit.ly/3xYzPhish": 0.3
        }
      },
      "nlp": {
        "model": "phishing_classifier_v1",
        "label": "unknown",
        "probability": 0.9524
      }
    }
  },
  "source": {},
  "destination": {}
}
```

### ECS Notes

The report borrows ECS field names so it is easy to map into an ECS-based index, but it has **not** been validated against the ECS spec or tested with a specific SIEM, and MailGuard does not ship logs anywhere.

| Field | Value | Notes |
|---|---|---|
| `@timestamp`, `event.created` | UTC ISO 8601 | |
| `event.kind` | `"alert"` | |
| `event.category` / `event.type` | `["email","threat"]` / `["indicator"]` | |
| `event.severity` | `1`–`4` | Maps to the four classification bands |
| `event.risk_score` | `0`–`100` | Same value as `mailguard.threat_score` |
| `mailguard.*` | | Custom namespace; needs its own mapping in any SIEM |
| `source.ip`, `destination.user.email` | always `{}` today | `generate_report()` accepts these, but `run_pipeline()` does not extract them yet |
| `mailguard.details.nlp.label` | always `"unknown"` today | The label is not passed through from inference yet |

## REST API Reference

| Endpoint | Method | Body | Returns |
|---|---|---|---|
| `/analyze` | `POST` | `{"email": "<raw eml, 10–1,000,000 chars>", "email_id": "<optional, ≤256 chars>"}` | Full JSON threat report (above). A UUID is generated if `email_id` is empty |
| `/predict` | `POST` | `{"email": "<body text, ≤1,000,000 chars>"}` | `{"prediction": "Phishing Email" \| "Safe Email", "confidence": 1.0}`. NLP model only (`models/artifacts/`); used by `frontend/index.html` |
| `/health` | `GET` | | `{"status": "ok", "version": "0.2.0", "timestamp": "..."}` |
| `/version` | `GET` | | `{"api": "0.2.0", "pipeline": "mailguard-soc-v1", "python": "..."}` |
| `/docs` | `GET` | | Interactive OpenAPI documentation |

The API has **no authentication or rate limiting**. Run it on localhost only.

**CORS:** browser origins are allowed only if listed in `MAILGUARD_CORS_ORIGINS` (comma-separated; default `http://localhost:8501`), with credentials disabled. The Streamlit dashboard calls the API server-side, so CORS does not affect it. To use `frontend/index.html`, serve it and allow its origin:

```bash
python -m http.server 5500 --directory frontend
```

Then start the API with `MAILGUARD_CORS_ORIGINS=http://localhost:8501,http://localhost:5500` (PowerShell: `$env:MAILGUARD_CORS_ORIGINS="http://localhost:8501,http://localhost:5500"`).

### Error Responses

| HTTP Code | When | Body |
|---|---|---|
| `422 Unprocessable Entity` | Request validation fails (e.g. `email` shorter than 10 or longer than 1,000,000 chars) | FastAPI/Pydantic default: `{"detail": [ { "type": "string_too_short" \| "string_too_long", ... } ]}` |
| `503 Service Unavailable` | Model artifact files are missing | `{"detail": "Model artifact not found. Run train_model.py first. (...)"}` |
| `500 Internal Server Error` | Any other unhandled exception | `{"error": "Internal server error", "request_id": "<uuid>", "path": "/analyze", "timestamp": "..."}`. Exception details are logged server-side under the same `request_id` and never returned to the client |

## Known Limitations

- **NLP model trained on old, narrow corpora.** The legitimate training mail is from 1992–2008 and largely mailing-list traffic. It scores F1 0.98 in-distribution but only 37% recall on unseen advance-fee fraud (see [Evaluation](#dataset--model-evaluation)).
- **The model partly learns era and writing style.** Even after masking, the top legitimate-class features include "wrote", "mailing list" and "unsubscribe", because the legitimate corpus is old mailing-list mail. Masking the leaked tokens barely moved CV F1 (0.984 → 0.983); it changed which features the model uses, not how well it scores in-distribution.
- **Only the NLP layer is benchmarked.** The dataset has no authentication headers, so the header and URL layers, and the combined score, have no measured accuracy.
- **No independent authentication checks.** SPF/DKIM/DMARC verdicts are only as trustworthy as the `Authentication-Results` header in the input; anyone crafting a raw `.eml` can write that header themselves.
- **Brand impersonation** uses substring matching and produces false positives.
- **Missing auth headers count as failures**, which raises the header score of legitimate emails that lack them.
- **WHOIS lookups are synchronous network calls** made during analysis; they slow requests and silently fail open when offline.
- **No attachment analysis**, despite the `MALWARE` band name.
- **Spoofing check is stricter than the alignment check.** A Return-Path on a subdomain of the From domain (common for newsletters) is flagged as a mismatch by HDR-004 even though the DMARC approximation treats it as aligned.
- **Score ceiling without URL signals.** NLP and header carry at most 65 of 100 points combined, so link-free attacks such as business email compromise (`samples/bec_wire_fraud.eml` scores 32) cannot reach the upper bands.
- **Simplified alignment.** Relaxed DMARC alignment is approximated as same domain or subdomain; real DMARC compares organisational domains using the Public Suffix List.

## Roadmap

- [x] Train on a real labelled corpus and publish precision / recall / false-positive rate
- [ ] Add modern legitimate mail (transactional, marketing) to reduce era and source bias
- [ ] Calibrate the decision threshold and probabilities on held-out data, and report a precision-recall curve
- [ ] End-to-end benchmark of the full pipeline on a corpus with complete headers
- [ ] Wire `check_blacklist()` to a threat feed (PhishTank, URLhaus, or SURBL) to activate URL-004 and CRIT-002
- [ ] Implement `resolve_redirects()` (HEAD request with timeout and redirect limit)
- [x] Extract URLs from HTML `href` attributes
- [x] DKIM `d=` alignment with the From domain
- [ ] Real DMARC: DNS lookup of the `_dmarc.<domain>` policy and Public Suffix List-based organisational-domain alignment
- [ ] Optional independent SPF/DKIM verification (e.g. `dkimpy`, `pyspf`)
- [ ] Attachment analysis (file-type checks, hashes, macro detection); rename the top score band until then
- [ ] Populate `source.ip` (from `Received` headers) and `destination.user.email`
- [ ] Tighten brand-impersonation matching (word boundaries, lookalike/homoglyph domains)
- [ ] Unit tests for header analysis, URL scoring, rule engine and API endpoints
- [x] Restricted CORS (environment-configured allow-list), input size limit, generic error responses
- [ ] API authentication, rate limiting, and async/background WHOIS lookups
- [ ] Log shipping and a validated mapping for Elasticsearch / Splunk / Sentinel

## Technology Stack

| Component | Technology |
|---|---|
| ML model | `scikit-learn` TF-IDF (1–2-grams) + LogisticRegression, benchmarked against GradientBoostingClassifier |
| Email parsing | Python stdlib `email` |
| URL analysis | `re`, `urllib.parse`, `python-whois` |
| REST API | `FastAPI` + `uvicorn`, `pydantic` v2 |
| Dashboard | `Streamlit` (+ `httpx` to call the API, `pandas` for the history table) |
| Tests | `pytest` |
| Output | ECS-style JSON |

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/url-blacklist-feed`
3. Implement your change inside the relevant module package
4. Keep the `run_pipeline(raw_email, email_id)` signature in `main.py` unchanged
5. Add or update tests in `tests/` and run `python -m pytest tests`
6. Open a pull request describing the new detection capability

## License

MIT License. See [LICENSE](LICENSE) for details.

Training data: *Phishing Email Curated Datasets* by A. I. Champa et al., [DOI 10.5281/zenodo.8339691](https://doi.org/10.5281/zenodo.8339691), used under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The dataset is downloaded at training time, not redistributed in this repository.
