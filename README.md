# ScamShield Pakistan

ScamShield Pakistan is an email phishing forensic analyzer - Web application (Flask)

## Features

- Header and metadata extraction
- Routing path and originating IP analysis
- SPF, DKIM, DMARC checks
- URL extraction and display/href mismatch detection
- Attachment hash extraction and risky extension detection
- WHOIS-based sender domain age checks
- DNS validation for SPF, DKIM, and DMARC records
- AbuseIPDB and VirusTotal integration (optional API keys)
- IOC extraction and HTML forensic report generation

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Optional API Keys

Create a `.env` file in the project root:

```env
VT_API=your_virustotal_api_key
ABUSEIPDB_API=your_abuseipdb_api_key
GROQ_API_KEY=your_groq_api_key
GEMINI_API_KEY=your_gemini_api_key
```

If keys are not present, those checks are skipped gracefully.

## Run Web App

```bash
python web_app.py
```

Then open:

http://127.0.0.1:5000

If port 5000 is blocked on your system, set a custom port:

```bash
# PowerShell
$env:WEB_APP_PORT="5050"
python web_app.py
```

## Web Workflow

- Upload a `.eml` file or paste raw email content.
- Click `Analyze Email`.
- Review risk score, metadata, authentication, URLs, attachments, and IOCs.
- Use the generated HTML report shown in the interface for export/reporting.
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
