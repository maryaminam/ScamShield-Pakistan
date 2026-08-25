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
