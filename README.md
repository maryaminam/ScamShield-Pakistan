# ScamShield Pakistan

ScamShield Pakistan is an email phishing forensic analyzer that now supports both:

- Desktop GUI mode (CustomTkinter)
- Web application mode (Flask)

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
```

If keys are not present, those checks are skipped gracefully.

## Run Desktop App

```bash
python forensic_gui.py
```

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
