"""Full regression test — all .eml files, direct analyzer (no server)."""
from pathlib import Path
from email_forensic_analyzer import EmailForensicAnalyzer

EML_DIR = Path(r"d:\ScamShield-Pakistan\test_emails")

eml_files = sorted(EML_DIR.glob("*.eml"))
print(f"Testing {len(eml_files)} emails...\n")

print(f"{'File':<48} {'Score':>5} {'Level':<10} {'SPF':>6} {'DKIM':>6}")
print("-" * 80)

for eml_path in eml_files:
    try:
        a = EmailForensicAnalyzer(eml_file=str(eml_path))
        auth = a.check_authentication()
        urls = a.extract_urls()
        atts = a.extract_attachments()
        patterns = a.detect_phishing_patterns()
        spoof = a.detect_spoofing()
        hdr = a.detect_header_anomalies()

        result = a.calculate_risk_score(
            auth=auth, urls=urls, attachments=atts, patterns=patterns,
            spoofing=spoof, header_anomalies=hdr,
        )
        score = result["score"]
        level = result["level"]
        spf = str(auth.get("spf", "—"))
        dkim = str(auth.get("dkim", "—"))
        print(f"{eml_path.name:<48} {score:>5} {level:<10} {spf:>6} {dkim:>6}")
    except Exception as exc:
        print(f"{eml_path.name:<48} ERROR: {exc}")
