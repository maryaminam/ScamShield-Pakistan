# Email Header Phishing Investigation Tool

A professional-grade, open-source desktop application for forensic analysis of phishing emails.  
Built in Python, this tool helps analysts parse `.eml` files, inspect email headers, validate authentication records, analyze URLs and attachments, enrich findings with threat intelligence, and generate exportable reports.

---

## 📌 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Risk Scoring Model](#risk-scoring-model)
- [Exports](#exports)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Author](#author)

---

## Overview

Phishing remains one of the most common initial attack vectors in modern cyber incidents.  
Manual email header analysis is slow and requires deep technical expertise.

The **Email Header Phishing Investigation Tool** automates this process by:

- Parsing RFC 5322-compliant email files (`.eml`)
- Tracing routing paths via `Received` headers
- Validating SPF, DKIM, and DMARC
- Detecting suspicious links and attachments
- Integrating external threat intelligence
- Producing a weighted risk score (0–100)
- Exporting professional forensic reports and IOC files

---

## Key Features

### ✅ Core Analysis
- Email metadata extraction (`From`, `To`, `Subject`, `Date`, `Message-ID`, etc.)
- Routing path reconstruction (hop-by-hop analysis)
- Timestamp anomaly detection (negative/future/excessive delays)
- Header identity mismatch detection (`From` vs `Reply-To`, `Return-Path`, DKIM domain)

### ✅ Authentication & DNS Validation
- SPF/DKIM/DMARC parsing from `Authentication-Results`
- Fallback to `Received-SPF` when needed
- Live DNS checks for:
  - SPF TXT (`v=spf1`)
  - DKIM selector records
  - DMARC TXT (`v=DMARC1`)

### ✅ URL, Attachment, and IOC Intelligence
- URL extraction from HTML and plaintext
- Display-text vs href domain mismatch detection
- Attachment extraction + MD5/SHA-256 hashing
- Dangerous extension detection
- IOC extraction (IPs, domains, URLs, emails, hashes)

### ✅ Threat Intelligence Integrations
- **ip-api.com** → geolocation/ISP/ASN
- **AbuseIPDB** → IP abuse confidence
- **VirusTotal** → file hash reputation
- **WHOIS** → domain age/registrar context

### ✅ Reporting & Export
- Professional HTML forensic reports
- JSON IOC export
- CSV IOC export
- Batch analysis summary support

---

## Architecture

This project uses a clean **two-layer architecture**:

1. **Backend Analysis Engine** (`email_forensic_analyzer.py`)  
   - Headless, testable forensic logic
2. **GUI Frontend** (`forensic_gui.py`)  
   - Modern CustomTkinter interface with 10 analysis tabs

The GUI uses background threads for network-dependent operations to avoid freezing.

---

## Screenshots

> Add your screenshots to a folder like `docs/images/`, then replace paths below.

### Dashboard
![Dashboard](docs/images/dashboard-placeholder.png)

### Metadata Tab
![Metadata](docs/images/metadata-placeholder.png)

### Routing Path Analysis
![Routing Path](docs/images/routing-placeholder.png)

### Authentication Results
![Authentication](docs/images/auth-placeholder.png)

### URL & Link Analysis
![URL Analysis](docs/images/url-analysis-placeholder.png)

### Attachment Analysis
![Attachment Analysis](docs/images/attachments-placeholder.png)

### Threat Intel
![Threat Intel](docs/images/threat-intel-placeholder.png)

### IOC Export
![IOC Export](docs/images/ioc-export-placeholder.png)

### HTML Report Preview
![HTML Report](docs/images/report-placeholder.png)

---

## Technology Stack

### Language
- Python 3.10+

### Third-Party Dependencies
- `customtkinter`
- `beautifulsoup4`
- `dnspython`
- `python-whois`
- `requests`

---

## Installation

### 1) Clone repository
```bash
git clone https://github.com/maryaminam/Email-Header-Phishing-Investigation-Tool.git
cd Email-Header-Phishing-Investigation-Tool
```

### 2) Create virtual environment (recommended)
```bash
python -m venv .venv
```

**Windows**
```bash
.venv\Scripts\activate
```

**Linux/macOS**
```bash
source .venv/bin/activate
```

### 3) Install dependencies
```bash
pip install -r requirements.txt
```

---

## Configuration

If you want full threat-intelligence functionality, set API keys as environment variables:

```bash
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

> `ip-api.com` works without an API key (rate limits apply).

---

## Usage

Run the GUI:

```bash
python forensic_gui.py
```

You can then:
1. Load a `.eml` file (or paste raw headers)
2. Run analysis
3. Review all tabs (metadata, auth, routing, URLs, attachments, threat intel)
4. Export report and IOCs

---

## Risk Scoring Model

The tool calculates a deterministic **0–100 score** using weighted forensic signals:

- Authentication failure (SPF/DKIM fail/softfail): **+25**
- URL display/href mismatch: **+20**
- Risky attachment extension: **+15**
- Young sender domain (<30 days): **+15**
- Abusive source IP (AbuseIPDB ≥25): **+10**
- Urgency language patterns: **+5**
- Credential theft language patterns: **+5**
- Brand impersonation patterns: **+5**

### Threat Levels
- **75–100**: Critical
- **50–74**: High
- **25–49**: Medium
- **0–24**: Low

---

## Exports

- **HTML Report**: complete forensic summary
- **JSON IOC Export**: structured indicator output
- **CSV IOC Export**: analyst-friendly flat format

---

## Project Structure

```text
Email-Header-Phishing-Investigation-Tool/
├── forensic_gui.py
├── email_forensic_analyzer.py
├── requirements.txt
├── README.md
└── docs/
    └── images/
```

---

## Roadmap

- Machine learning-assisted phishing classification
- IMAP mailbox ingestion workflow
- STIX/TAXII export format support
- Analyst case management enhancements
- Expanded IOC enrichment sources

---

## Disclaimer

This tool is intended for **defensive cybersecurity, incident response, and educational use only**.  
Users are responsible for compliance with all applicable laws, API provider terms, and organizational policies.

---

## Author

**Maryam Inam**  
GitHub: [@maryaminam](https://github.com/maryaminam)
