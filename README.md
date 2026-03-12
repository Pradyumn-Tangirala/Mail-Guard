<div align="center">

# 🛡️ MailGuard

### SOC-Grade Multi-Layered Email Threat Detection Pipeline

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.55-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![SIEM Ready](https://img.shields.io/badge/Output-ECS%2FSIEM%20Ready-blueviolet?style=flat-square)](#json-output-format)

*Evolved from a simple NLP phishing classifier into a modular, analyst-grade threat detection engine with layered signals, a rule engine, and structured SIEM-ready output.*

</div>

## Overview

MailGuard is a **production-grade email threat detection pipeline** designed to support Security Operations teams. It moves beyond a single ML model by combining three independent analysis layers — natural language processing, URL intelligence, and email authentication forensics — into a single weighted threat score with rule-level explainability.

Every analysis produces a **structured JSON log** aligned with the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html), making it directly ingestible by SIEM platforms such as Elasticsearch/Kibana, Splunk Enterprise Security, and Microsoft Sentinel.

## Pipeline Architecture

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                     RAW EMAIL INPUT (.eml)                      │
  └───────────────────────────┬─────────────────────────────────────┘
                              │
                              ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  STAGE 1 · PREPROCESSING                preprocessing/          │
  │──────────────────────────────────────────────────────────────── │
  │  parse_raw_email()  →  clean_text()  →  extract_features()      │
  │  Python stdlib email parser · HTML stripping · tokenisation     │
  └──────┬──────────────────────┬──────────────────────────────────┘
         │                      │
         ▼                      ▼
  ┌─────────────────┐   ┌──────────────────────────────────────────┐
  │  STAGE 2        │   │  STAGE 3                                 │
  │  URL ANALYSIS   │   │  HEADER ANALYSIS                         │
  │  url_analysis/  │   │  header_analysis/                        │
  │─────────────────│   │──────────────────────────────────────────│
  │ • Regex extract │   │ • SPF evaluation (pass/fail/softfail)    │
  │ • IP-host URLs  │   │ • DKIM signature verification            │
  │ • Shorteners    │   │ • DMARC domain alignment check           │
  │ • WHOIS domain  │   │ • From / Return-Path mismatch            │
  │   age (<30 days)│   │ • Reply-To hijack detection              │
  │ • Threat feeds  │   │ • Display-name brand impersonation       │
  │ • Per-URL score │   │ • Composite header threat score          │
  └────────┬────────┘   └─────────────────────┬────────────────────┘
           │                                   │
           └──────────────┬────────────────────┘
                          │
                          ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  STAGE 4 · ML MODEL INFERENCE                      models/      │
  │──────────────────────────────────────────────────────────────── │
  │  GradientBoostingClassifier + TF-IDF (5 000 features)           │
  │  load_model()  →  run_inference()  →  threat_probability float  │
  └───────────────────────────┬─────────────────────────────────────┘
                              │
                              ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  STAGE 5 · THREAT SCORING ENGINE            threat_scoring/     │
  │──────────────────────────────────────────────────────────────── │
  │                                                                 │
  │  Score = NLP×0.40 + URL×0.35 + Header×0.25  →  0-100           │
  │                                                                 │
  │  ┌──────────┬─────────────┬───────────┬──────────────────────┐ │
  │  │  0 – 29  │   30 – 54   │  55 – 79  │      80 – 100        │ │
  │  │  🟢 SAFE │🟡 SUSPICIOUS│🟠 PHISHING│    🔴 MALWARE        │ │
  │  └──────────┴─────────────┴───────────┴──────────────────────┘ │
  │                                                                 │
  │  14-rule detection engine (URL / HDR / NLP / CRIT categories)   │
  │  generate_report()  →  ECS-aligned SIEM JSON                   │
  └──────────┬───────────────────────────────────────┬─────────────┘
             │                                       │
             ▼                                       ▼
  ┌──────────────────────┐             ┌─────────────────────────┐
  │  FastAPI REST API    │             │  Streamlit Dashboard    │
  │  api/app.py          │             │  dashboard/app.py       │
  │──────────────────────│             │─────────────────────────│
  │  POST /analyze       │             │  Threat score gauge     │
  │  POST /predict       │             │  Rule table             │
  │  GET  /health        │             │  Header drill-down      │
  │  GET  /version       │             │  URL analysis view      │
  │  OpenAPI /docs       │             │  Raw SIEM JSON viewer   │
  └──────────────────────┘             └─────────────────────────┘
```

## Key Features

| Capability | Details |
|---|---|
| **Multi-layer scoring** | NLP (40%), URL (35%), Header (25%) — independently weighted |
| **14-rule detection engine** | URL-001–005, HDR-001–005, NLP-001–002, CRIT-001–002 |
| **Email authentication forensics** | SPF / DKIM / DMARC evaluation from raw headers |
| **Spoofing detection** | From/Return-Path mismatch, Reply-To hijacking, display-name brand impersonation |
| **URL intelligence** | IP-based URL detection, shortener recognition, WHOIS domain-age check |
| **SIEM-ready JSON output** | ECS-aligned schema — plug into Elasticsearch, Splunk, or Sentinel |
| **FastAPI REST layer** | `/analyze` for full pipeline, `/predict` for legacy compatibility |
| **Streamlit SOC dashboard** | Real-time gauge, rule table, session history, raw JSON viewer |

## Directory Structure

```
Mail-Guard/
│
├── main.py                     ← Pipeline entry point & CLI
├── train_model.py              ← Train and serialize the ML model
├── requirements.txt
│
├── data/
│   └── email.csv               ← Training dataset
│
├── models/
│   ├── __init__.py
│   └── artifacts/
│       ├── model.pkl           ← Trained GradientBoostingClassifier
│       └── vectorizer.pkl      ← Fitted TF-IDF vectorizer
│
├── preprocessing/
│   └── __init__.py             ← Email parsing, cleaning, feature extraction
│
├── url_analysis/
│   ├── __init__.py
│   └── scanner.py              ← URL extraction, scoring, WHOIS checks
│
├── header_analysis/
│   ├── __init__.py
│   └── analyzer.py             ← SPF/DKIM/DMARC, spoofing detection
│
├── threat_scoring/
│   ├── __init__.py
│   └── engine.py               ← Weighted aggregation, rule engine, SIEM JSON
│
├── api/
│   ├── __init__.py
│   └── app.py                  ← FastAPI application
│
├── dashboard/
│   ├── __init__.py
│   └── app.py                  ← Streamlit security dashboard
│
└── backend/                    ← Legacy FastAPI server (preserved)
    └── app.py
```

## Quick Start

### Prerequisites

```bash
pip install fastapi uvicorn[standard] streamlit httpx pydantic \
            scikit-learn pandas python-whois
```

### 1. Train the model

```bash
python train_model.py
# Output: models/artifacts/model.pkl  +  models/artifacts/vectorizer.pkl
# Prints: Accuracy score + classification report
```

### 2. Start the API server

```bash
# Via main.py CLI (recommended)
python main.py api --port 5000

# Or directly with uvicorn (supports --reload for development)
uvicorn api.app:app --host 0.0.0.0 --port 5000 --reload
```

Interactive API docs: **http://localhost:5000/docs**

### 3. Launch the dashboard

```bash
# Via main.py CLI
python main.py dashboard --port 8501

# Or directly with Streamlit
streamlit run dashboard/app.py
```

Dashboard: **http://localhost:8501**

### 4. Analyze an email from the command line

```bash
# From a .eml file
python main.py analyze --email-file samples/test.eml --id eml-001

# From stdin
cat samples/test.eml | python main.py analyze --id eml-002
```

### 5. Call the API directly

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email": "From: attacker@phish.net\r\nSubject: Urgent\r\n\r\nClick here: http://1.2.3.4/login", "email_id": "test-001"}'
```

## Detection Rules

| Rule ID | Category | Trigger Condition |
|---|---|---|
| `URL-001` | URL | IP-address used as hostname (`http://1.2.3.4/...`) |
| `URL-002` | URL | Known URL shortener detected (`bit.ly`, `tinyurl.com`, etc.) |
| `URL-003` | URL | Domain registered < 30 days ago (via WHOIS) |
| `URL-004` | URL | URL present on threat intelligence blacklist |
| `URL-005` | URL | Aggregate URL score ≥ 0.70 |
| `HDR-001` | Header | SPF record fail or not found |
| `HDR-002` | Header | DKIM signature fail or not found |
| `HDR-003` | Header | DMARC domain alignment failure |
| `HDR-004` | Header | Spoofing indicator (mismatch / impersonation) |
| `HDR-005` | Header | Composite header score ≥ 0.60 |
| `NLP-001` | NLP | ML model phishing probability ≥ 0.80 |
| `NLP-002` | NLP | ML model phishing probability 0.50 – 0.79 |
| `CRIT-001` | Critical | All three layers triggered simultaneously |
| `CRIT-002` | Critical | Blacklisted URL + spoofing indicators combined |

Rules are evaluated independently. The rule system is **additive and separate from scoring** — new rules can be added at any time without modifying the weight system.

## JSON Output Format

All threat reports follow a schema aligned with the **[Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)**, making them directly ingestible by SIEM platforms without custom field mapping.

```json
{
  "@timestamp": "2026-03-12T10:04:12.601277+00:00",

  "event": {
    "kind":      "alert",
    "category":  ["email", "threat"],
    "type":      ["indicator"],
    "severity":  3,
    "risk_score": 76,
    "dataset":   "mailguard.threat",
    "provider":  "mailguard",
    "action":    "phishing"
  },

  "mailguard": {
    "email_id":       "msg-2026-phish-001",
    "threat_score":   76,
    "classification": "PHISHING",

    "triggered_rules": [
      { "rule_id": "URL-001", "description": "IP-based URL detected: ['http://192.168.1.100/login']" },
      { "rule_id": "HDR-001", "description": "SPF authentication failure: spf=fail" },
      { "rule_id": "HDR-004", "description": "Spoofing indicator: ['display_name_impersonation:paypal']" },
      { "rule_id": "NLP-001", "description": "ML model high-confidence phishing prediction (>=0.80): probability=0.87" },
      { "rule_id": "CRIT-001", "description": "CRITICAL: All three layers triggered simultaneously (NLP + URL + Header)" }
    ],
    "triggered_rule_count": 9,

    "signals": {
      "nlp_score":    0.87,
      "url_score":    0.55,
      "header_score": 0.89,
      "normalized":   0.763
    },

    "details": {
      "header": {
        "spf":   { "raw": "spf=fail",  "passed": false, "score": 1.0 },
        "dkim":  { "raw": "dkim=fail", "passed": false, "score": 0.8 },
        "dmarc": { "passed": false, "aligned": false,
                   "from_domain": "evil-domain.com", "return_path_domain": "phish.net" },
        "spoofing_flags": [
          "from_return_path_mismatch:evil-domain.com vs phish.net",
          "display_name_impersonation:paypal"
        ]
      },
      "url": {
        "total_urls": 2,
        "ip_based":   ["http://192.168.1.100/login"],
        "shortened":  ["https://bit.ly/3xYzAb"],
        "newly_registered": [],
        "blacklisted":      [],
        "per_url_scores": {
          "http://192.168.1.100/login": 0.55,
          "https://bit.ly/3xYzAb":     0.30
        }
      },
      "nlp": {
        "model":       "phishing_classifier_v1",
        "probability": 0.87
      }
    }
  },

  "source":      { "ip": "203.0.113.42" },
  "destination": { "user": { "email": "victim@company.com" } }
}
```

### ECS Field Mapping for SIEM

| ECS Field | MailGuard Value | Purpose |
|---|---|---|
| `event.kind` | `"alert"` | Marks as actionable alert |
| `event.severity` | `1`–`4` | Maps to SAFE/SUSPICIOUS/PHISHING/MALWARE |
| `event.risk_score` | `0`–`100` | Native Kibana SIEM risk scoring |
| `event.category` | `["email","threat"]` | ECS category routing |
| `@timestamp` | UTC ISO 8601 | Chronological SIEM indexing |
| `source.ip` | Sender MTA IP | Network correlation |

## REST API Reference

| Endpoint | Method | Body | Returns |
|---|---|---|---|
| `/analyze` | `POST` | `{"email": "<raw eml>", "email_id": "<optional>"}` | Full SIEM threat report |
| `/predict` | `POST` | `{"email": "<body text>"}` | `{"prediction": "...", "confidence": 0.97}` |
| `/health` | `GET` | — | `{"status": "ok", "version": "0.2.0"}` |
| `/version` | `GET` | — | API + Python version strings |
| `/docs` | `GET` | — | Interactive OpenAPI documentation |

### Error Responses

All errors return structured JSON — never HTML:

```json
{
  "error": "FileNotFoundError",
  "detail": "Model artifact not found. Run train_model.py first.",
  "path": "/analyze",
  "timestamp": "2026-03-12T10:00:00+00:00"
}
```

| HTTP Code | Meaning |
|---|---|
| `501 Not Implemented` | A pipeline module is still a stub |
| `503 Service Unavailable` | Model artifact not found (run `train_model.py`) |
| `422 Unprocessable Entity` | Pydantic validation failure (email too short, etc.) |

## Technology Stack

| Component | Technology |
|---|---|
| ML Model | `scikit-learn` GradientBoostingClassifier + TF-IDF |
| Email parsing | Python stdlib `email` module |
| URL intelligence | `re` + `python-whois` |
| REST API | `FastAPI` + `uvicorn` |
| Dashboard | `Streamlit` |
| API client | `httpx` |
| Data validation | `pydantic` v2 |
| Output schema | Elastic Common Schema (ECS) |

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/url-blacklist-feed`
3. Implement your change inside the relevant module package
4. Ensure `main.py` pipeline contract is preserved (do not change `run_pipeline()` signature)
5. Open a pull request with a description of the new detection capability

## License

MIT License — see [LICENSE](LICENSE) for details.

<div align="center">
<sub>Built for security analysts who need more than a binary classifier.</sub>
</div>
