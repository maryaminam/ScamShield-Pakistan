# Email Header Phishing Investigation Tool

A professional-grade, open-source desktop application for forensic analysis of phishing emails.  
Built in Python, this tool helps analysts parse `.eml` files, inspect email headers, validate authentication records, analyze URLs and attachments, enrich findings with threat intelligence, and generate exportable reports.

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
<img width="975" height="532" alt="image" src="https://github.com/user-attachments/assets/3549d880-11ec-4d41-a931-07c82b55b22b" />

---

## GUI


### Dashboard
<img width="975" height="515" alt="image" src="https://github.com/user-attachments/assets/2c4b05dc-1b8b-40a2-bbb6-65cc8e9dd2ab" />

### Metadata Tab
<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/f5ac4424-c38e-4846-b92f-7f45c31cde87" />

### Routing Path Analysis
<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/570e3047-ccfc-472b-98a3-8bb995308fb0" />

### Authentication Results
<img width="975" height="516" alt="image" src="https://github.com/user-attachments/assets/2dbcd3f0-de6d-45a1-b269-e997e8f29e9e" />

### URL & Link Analysis
<img width="975" height="438" alt="image" src="https://github.com/user-attachments/assets/5a6f2d1b-3697-42c7-8527-d18a5e9ec16b" />

### Attachment Analysis
<img width="975" height="518" alt="image" src="https://github.com/user-attachments/assets/2408f2a2-fe5d-4695-86d2-bbb02c754e5d" />

### Threat Intel
<img width="975" height="439" alt="image" src="https://github.com/user-attachments/assets/97b9fb14-a216-420c-bcda-fd836868cfdb" />

### IOC Export
<img width="975" height="431" alt="image" src="https://github.com/user-attachments/assets/38bb90c9-f8b4-4a95-9d57-c5acb2b0bd56" />

### HTML Report Preview
<img width="975" height="515" alt="image" src="https://github.com/user-attachments/assets/20d7901e-a40e-401b-8ade-75afbfba2fe3" />

---
## Data Flow & Processing Pipeline

<img width="975" height="532" alt="image" src="https://github.com/user-attachments/assets/3b3d4563-0d17-4239-865b-bc5db96bfcc4" />

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
