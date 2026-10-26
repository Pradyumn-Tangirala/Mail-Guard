# Sample Emails

Raw `.eml` files for trying the pipeline:

```bash
python main.py analyze --email-file samples/test.eml
```

All samples are synthetic. Domains use reserved names (`.test`, `example.com`, `example.org`) and IPs come from documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`), so no sample points at a real host. Brand names appear only as the lure text an attacker would use.

| File | Scenario | Intended | Observed score / verdict | Rules fired |
|---|---|---|---|---|
| `phishing.eml` | PayPal-themed credential phish: SPF/DKIM fail, spoofed envelope, IP-host URL + shortener | Malicious | 80 / `MALWARE` ¹ | URL-001, URL-002, HDR-001…005, NLP-001, CRIT-001 |
| `test.eml` | "Document shared with you" lure: SPF softfail, no DKIM, shortened link | Malicious | 57 / `PHISHING` | URL-002, HDR-001, HDR-002, HDR-004, NLP-001, CRIT-001 |
| `html_credential_phish.eml` | Microsoft 365 password-expiry lure; HTML-only link to a bare IP | Malicious | 73 / `PHISHING` | URL-001, HDR-001, HDR-002, HDR-004, HDR-005, NLP-001, CRIT-001 |
| `bec_wire_fraud.eml` | CEO wire-transfer fraud from a lookalike domain with passing SPF/DKIM, Reply-To to free mail, no links | Malicious | 32 / `SUSPICIOUS` | HDR-004, NLP-002 |
| `legit_newsletter.eml` | Opt-in newsletter, SPF/DKIM/DMARC pass, bounce address on a subdomain | Benign | 12 / `SAFE` | HDR-004 ² |
| `benign.eml` | Internal meeting reminder, SPF/DKIM pass | Benign | 11 / `SAFE` | none |

Observed with the committed model (TF-IDF + Logistic Regression trained on Nazario_5, see the main README) on 2026-10-25. URL scores can change if WHOIS is reachable. With the previous 7-sentence toy model, only `phishing.eml` was flagged; the other three malicious samples scored `SAFE`.

These are six hand-written emails, not a benchmark; the model was not tuned on them. They are kept as regression cases, including for known gaps (see *Known Limitations* in the main README):

- **`html_credential_phish.eml`**: the only link lives in an `href` attribute. URLs are now extracted from the raw body, so URL-001 fires and the score rose from 53 (`SUSPICIOUS`) to 73 (`PHISHING`). It is kept as a regression test for that fix.
- **`bec_wire_fraud.eml`**: there are no URLs and authentication passes for the lookalike domain. It only just reaches `SUSPICIOUS` (32), driven by the NLP layer (0.68) and the Reply-To mismatch.
- **Score ceiling without URL signals:** NLP and header together carry at most 65 of 100 points, so a link-free attack like `bec_wire_fraud.eml` can never reach the upper bands.
- ¹ **`phishing.eml`**: `MALWARE` is just the name of the 80–100 score band; no attachment analysis exists.
- ² **`legit_newsletter.eml`**: false-positive spoofing flag. The spoofing check compares From (`example.org`) and Return-Path (`news.example.org`) by exact match, while the DMARC-alignment check accepts subdomains.
