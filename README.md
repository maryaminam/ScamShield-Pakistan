# ScamShield Pakistan

A multi-layered email phishing forensic analyzer and URL scanner with a modern async web dashboard, local ML classification, and AI-powered plain-English explanations.

### Dashboard
<img width="1918" height="861" alt="image" src="https://github.com/user-attachments/assets/1a417600-7ced-4c2e-8426-e28a8ee6714b" />


### Email Analyzer
<img width="1906" height="865" alt="image" src="https://github.com/user-attachments/assets/4dd6f27e-c089-4811-bd08-f105a3644fc0" />

<img width="1918" height="871" alt="image" src="https://github.com/user-attachments/assets/96562adc-bbf2-48c4-afbf-9cf4e8b238ce" />

<img width="1905" height="867" alt="image" src="https://github.com/user-attachments/assets/f2547c73-27bb-4681-af19-d76f45261628" />

### URL Analyzer
<img width="1905" height="861" alt="image" src="https://github.com/user-attachments/assets/f8328767-b408-4007-b99b-e3f21e2d7732" />

<img width="1905" height="787" alt="image" src="https://github.com/user-attachments/assets/6c4b0134-b550-4a4f-a45d-8cd99d4f76e1" />

<img width="1901" height="872" alt="image" src="https://github.com/user-attachments/assets/42ea9ca5-5efc-4fc3-937b-4262bc4941cd" />




## Features

### Email Forensics
- **Header & metadata extraction** — From, To, Subject, Date, Message-ID, Return-Path
- **Routing path analysis** — hop-by-hop chronological reconstruction from Received headers, originating public IP detection
- **Authentication checks** — SPF, DKIM, DMARC, and Microsoft CompAuth from `Authentication-Results` headers, with `Received-SPF` fallback
- **URL extraction & mismatch detection** — HTML `<a>` tag parsing with display-text vs. href domain comparison, redirect resolution, ESP same-root tolerance
- **URL path analysis** — brand keyword and phishing lure term detection in link paths/filenames
- **Homograph & punycode detection** — IDN homograph attacks via punycode, NFKD normalization, character substitution (1→l, 0→o), Levenshtein distance against known brands and Tranco top-5K [...]
- **Attachment analysis** — MD5 + SHA-256 hashing, risky extension detection (20+ types including executables, macros, archives), brand-keyword mismatch in filenames
- **Sender domain reputation** — WHOIS + RDAP fallback for domain age; flags domains registered < 30 days ago
- **URL domain reputation** — concurrent WHOIS, VirusTotal, and AbuseIPDB lookups on linked domains (up to 3 unique)
- **DNS record validation** — concurrent queries for SPF, DMARC, and 9 DKIM selectors
- **IP intelligence** — AbuseIPDB abuse-confidence scoring, ip-api.com geolocation (country, city, ISP, ASN)
- **VirusTotal integration** — domain and file-hash scanning via VT v3 API
- **Spoofing detection** — 5 independent checks: brand impersonation in display name, freemail with corporate persona, display-name vs. local-part mismatch (friendly-from spoof), Reply-To diverg[...]
- **Header anomaly detection** — From vs. Reply-To / Return-Path / DKIM signing domain mismatches, with ESP subdomain tolerance
- **Timestamp analysis** — time-travel detection, excessive hop delays (>4 hours), future-dated Date headers
- **Forensic X-Headers** — X-Mailer, X-Originating-IP, X-Spam-Status, and 9 more
- **Phishing language detection** — regex patterns for urgency, credential harvesting, and brand impersonation with combining-diacritic normalization and legitimate-brand-URL filtering
- **ML text classification** — local zero-shot classifier (DistilBERT-MNLI) detecting urgency, credential theft, brand impersonation, and social manipulation beyond regex
- **IOC extraction** — aggregated IPs, domains, URLs, emails, and file hashes
- **HTML forensic report** — self-contained downloadable report with risk banner, print CSS

### URL Scanner
- **Lexical analysis** — Shannon entropy (DGA detection), embedded credentials (@ trick), percent-encoding density, non-standard ports, IP-literal URLs, HTTPS, suspicious TLDs, excessive subdoma[...]
- **Redirect resolution** — follows up to 5 redirects with SSRF protection (blocks private IP resolution)
- **Homograph detection** — punycode, Levenshtein distance against brand + Tranco top-5K domains
- **Brand keyword analysis** — domain and path/filename brand impersonation checks
- **Live page content inspection** — password input fields, cross-domain form actions, brand impersonation in page titles
- **Reputation enrichment** — concurrent WHOIS, VirusTotal URL scan, and AbuseIPDB IP check
- **0–100 risk score** with Critical / High / Medium / Low classification

### AI Explanation Layer
- **Provider chain** — Groq (openai/gpt-oss-20b) → Google Gemini (gemini-3.6-flash) → deterministic template fallback
- **Structured output** — Pydantic-validated JSON schema (plain summary, key concerns, what this means, recommended actions)
- **Hallucination guard** — verified-entity extraction; replaces fabricated concerns with verified signals; falls back to deterministic summary on invented domains
- **Signal-strength annotations** — classifies each scoring signal as conclusive / strong / moderate / weak for LLM emphasis guidance
- **Risk-level tone** — urgent for Critical, reassuring for Low
- **In-process caching** — SHA-256 keyed to avoid duplicate LLM calls

### Web Dashboard
- **FastAPI async server** with Uvicorn
- **SSE streaming** — real-time analysis progress (parsing → auth → URLs → patterns → enrichment → scoring)
- **3-page SPA** — Dashboard (stats + activity table), Email Analysis (upload/paste + 11 result tabs), URL Analysis
- **Light/dark theme** with CSS variables and localStorage persistence
- **Animated pill navigation** (GSAP), glassmorphism cards, animated risk gauge rings
- **Inline tooltip glossary** — 17 technical terms auto-wrapped with explanations
- **Security headers** — CSP, HSTS, X-Frame-Options, Referrer-Policy, X-Content-Type-Options
- **Rate limiting** — sliding window per IP (30 req/min email, 20 URL, 10 AI)
- **Auto port discovery** — falls back to next available port if 5000 is occupied

---

## Risk Scoring Model

The tool calculates a deterministic **0–100 score** using 17+ weighted forensic signals:

| Signal | Weight | Description |
|--------|--------|-------------|
| Credential language | +40 | Credential-harvesting phrases (password, SSN, etc.) |
| CompAuth failure | +25 | Microsoft composite authentication failed |
| Homograph domain | +25 | Link domain mimics a known brand via punycode |
| URL path brand spoof | +25 | Brand keyword in link path not matching domain |
| Auth failure | +22 | SPF/DKIM/DMARC fail or softfail |
| Spoofing | +20 | Display-name / Reply-To / Return-Path spoofing (diminishing returns) |
| Urgency language | +20 | Urgency phrases with ML reinforcement bonus |
| URL mismatch | +18 | Display/href domain mismatch |
| Header anomaly | +15 | DKIM signing domain mismatch |
| Young URL domain | +14 | Linked domain recently registered |
| Risky attachment | +13 | Dangerous file extension |
| Young domain | +12 | Sender domain < 30 days old |
| ML manipulation | +12 | Zero-shot classifier caught what regex missed |
| Brand impersonation | +10 | Brand keywords in subject/body |
| URL path lure | +10 | Phishing lure terminology in link path |
| AbuseIP URL | +20 | Linked domain IP flagged by AbuseIPDB |
| VT URL malicious | +25 | Linked domain flagged by VirusTotal |
| Abuse IP | +8 | Originating IP flagged on AbuseIPDB |
| Attachment brand spoof | +20 | Brand keyword in attachment filename |

**ML bonuses**: high-confidence (≥75%) ML predictions reinforce existing regex signals with up to 50% additional weight.

**Content-signal cap**: when the sender domain is verified as old and no hard indicators (auth fail, URL mismatch, risky attachment, etc.) are present, soft signals are capped at 20 points and cr[...]

### Threat Levels

| Score | Level |
|-------|-------|
| 75–100 | Critical |
| 50–74 | High |
| 25–49 | Medium |
| 0–24 | Low |

---

## Tech Stack

- **Python 3.13** with FastAPI + Uvicorn (async web server)
- **BeautifulSoup4** for HTML email parsing
- **dnspython** + **aiodns** for DNS record validation
- **python-whois** + RDAP for domain age checks
- **httpx** for async HTTP (VirusTotal, AbuseIPDB, geolocation)
- **HuggingFace Transformers** + **PyTorch** for zero-shot ML classification (DistilBERT-MNLI)
- **Groq SDK** + **Google GenAI SDK** for AI explanations
- **Pydantic v2** for structured LLM output validation
- **GSAP** for frontend navigation animations
- **Tailwind CSS** (CDN) for utility-first styling
- **Inter** + **Outfit** fonts from Google Fonts

---

## Setup

1. Create and activate a virtual environment:

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. (Optional) Create a `.env` file in the project root for API keys:

```env
VT_API=your_virustotal_api_key
ABUSEIPDB_API=your_abuseipdb_api_key
GROQ_API_KEY=your_groq_api_key
GEMINI_API_KEY=your_gemini_api_key
```

Keys that are not present are skipped gracefully — the tool works without them.

---

## Usage

### Run the Web App

```bash
python web_app.py
```

Then open [http://127.0.0.1:5000](http://127.0.0.1:5000).

If port 5000 is blocked, set a custom port:

```powershell
# PowerShell
$env:WEB_APP_PORT="5050"
python web_app.py
```

### Web Workflow

1. **Dashboard** — view session statistics and recent scan activity
2. **Email Analysis** — upload a `.eml` file or paste raw email content, click "Analyze email", watch real-time progress, then explore 11 result tabs (Overview, AI Summary, Authentication, Spoo[...]
3. **URL Analysis** — enter any URL, click "Scan URL", review risk score and indicators, optionally toggle the AI Summary

### CLI Usage (Core Analyzer)

```bash
python email_forensic_analyzer.py path/to/email.eml
```

---

## Exports

- **HTML Forensic Report** — self-contained downloadable report with risk banner, all sections, and print-optimized CSS
- **IOCs** — clickable copy-to-clipboard indicators (IPs, domains, URLs, emails, file hashes) in the web UI

---

## Project Structure

```text
ScamShield-Pakistan/
├── email_forensic_analyzer.py   # Core analysis engine (3019 lines)
├── url_analyzer.py              # Standalone URL scanner (710 lines)
├── ai_explainer.py              # AI explanation layer (910 lines)
├── nlp_phishing_classifier.py   # Local ML classifier (128 lines)
├── web_app.py                   # FastAPI web server (601 lines)
├── generate_report.py           # Report generation utilities
├── templates/
│   └── index.html               # Web dashboard SPA (1739 lines)
├── static/
│   ├── app.js                   # Client-side JS (563 lines)
│   └── pill-nav.css             # Navigation styles (302 lines)
├── test_emails/                 # 20+ curated test .eml files
├── tranco_top_10k.txt           # Top domains for homograph detection
├── requirements.txt             # Python dependencies
├── runtime.txt                  # Python version pin (3.13.3)
├── .env                         # API keys (not committed)
└── .gitignore
```

---

## Test Emails

The `test_emails/` directory contains 20+ curated `.eml` files covering:

- Clean legitimate emails
- SPF/DKIM/DMARC authentication failures
- Brand impersonation (PayPal, Alibaba)
- Freemail with corporate display name
- Reply-To and Return-Path divergence
- URL display/href mismatch
- Risky executable attachments
- Phishing urgency and credential-harvesting language
- Timestamp anomalies
- Young domain (WHOIS)
- Combined critical indicators
- Adversarial and real-world emails

### External datasets used for testing

I also tested the system using the following external datasets:

- Emails: [phishing_pot](https://github.com/rf-peixoto/phishing_pot/tree/main) — a public collection of phishing emails used to validate the email forensics and detection pipeline.
- URLs: [Phishing Site URLs (Kaggle)](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) — a labeled dataset of phishing site URLs used to validate the URL scanner and risk scoring.

---

## Roadmap

- IMAP mailbox ingestion workflow
- STIX/TAXII export format support
- Analyst case management enhancements
- Expanded IOC enrichment sources
- Batch email analysis

---

## Disclaimer

This tool is intended for **defensive cybersecurity, incident response, and educational use only**.
Users are responsible for compliance with all applicable laws, API provider terms, and organizational policies.

---

## Author

**Maryam Inam**
GitHub: [@maryaminam](https://github.com/maryaminam)
