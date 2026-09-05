# Test .eml files

One file per scenario. All IPs are documentation/test ranges (192.0.2.x,
198.51.100.x, 203.0.113.x) or known-bad sample ranges; no real targets.

| File | Triggers | Expected verdict |
|------|----------|------------------|
| 01_clean_legitimate.eml | none | Low (~0) |
| 02_auth_failure_spf_dkim_dmarc.eml | `check_authentication` (SPF/DKIM/DMARC fail) | High |
| 03_brand_impersonation_paypal.eml | `detect_spoofing` (brand impersonation) | High |
| 04_freemail_corporate_persona.eml | `detect_spoofing` (free-mail + corporate display name) | High |
| 05_reply_to_divergence.eml | `detect_spoofing` (Reply-To → free webmail) | High |
| 06_url_display_href_mismatch.eml | `extract_urls` (display/href mismatch) | High |
| 07_risky_attachment_exe.eml | `extract_attachments` (.pdf.exe) + auth softfail | High |
| 08_phishing_language_urgency_credential.eml | `detect_phishing_patterns` (urgency + credential + impersonation) | Medium |
| 09_timestamp_anomalies.eml | `analyze_timestamps` (time-travel, gap, future Date) | Medium |
| 10_critical_combined_indicators.eml | almost every signal at once | Critical |
| 11_young_domain_whois.eml | `check_domain_reputation` (depends on live WHOIS) | Medium |
| 12_return_path_divergence.eml | `detect_spoofing` (Return-Path divergence) + DMARC fail | High |

## Run individually
```
python forensic_gui.py
# then File -> Open -> pick a file from this folder
```

## Run as a batch
```
python forensic_gui.py
# Sidebar -> "Batch Analyze" -> pick this folder
# produces test_emails/batch_report.html
```

## Run from CLI
```
python email_forensic_analyzer.py test_emails/10_critical_combined_indicators.eml
```

### External datasets used for testing

I also tested the system using the following external datasets and included them in validation runs:

- Emails: [phishing_pot](https://github.com/rf-peixoto/phishing_pot/tree/main) — a public collection of phishing emails used to validate the email forensics and detection pipeline.
  - Short usage example:
    ```bash
    # clone the phishing_pot repo and copy .eml samples into a local folder
    git clone https://github.com/rf-peixoto/phishing_pot.git /tmp/phishing_pot
    mkdir -p test_emails/external_phishing_pot
    cp /tmp/phishing_pot/*.eml test_emails/external_phishing_pot/

    # run the analyzer over all copied .eml files (CLI batch)
    for f in test_emails/external_phishing_pot/*.eml; do
      python email_forensic_analyzer.py "$f" >> test_emails/external_phishing_pot/results.log
    done
    ```

- URLs: [Phishing Site URLs (Kaggle)](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) — a labeled dataset of phishing site URLs used to validate the URL scanner and risk scoring.
  - Short usage example:
    ```bash
    # download the Kaggle dataset (via kaggle CLI) and extract the URLs column to a file
    kaggle datasets download -d taruntiwarihp/phishing-site-urls -p /tmp --unzip
    # assume the CSV extracted to /tmp/phishing_site_urls.csv and contains a column named "url"
    cut -d',' -f1 /tmp/phishing_site_urls.csv | sed '1d' > test_emails/external_phishing_urls.txt

    # run the URL scanner over the first 100 URLs and collect results
    mkdir -p test_emails/url_results
    head -n 100 test_emails/external_phishing_urls.txt | while read u; do
      python url_analyzer.py "$u" > "test_emails/url_results/$(echo "$u" | md5sum | cut -d' ' -f1).json"
    done
    ```

If you'd like, I can add these sample folders (external_phishing_pot, url_results) to the repository as examples (empty placeholder + README) or import a small sample of records into test_emails/ for reproducible CI-like tests.
