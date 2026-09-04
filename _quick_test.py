"""Quick test for legitimate_email.eml — direct analyzer, no server."""
from email_forensic_analyzer import EmailForensicAnalyzer

a = EmailForensicAnalyzer(eml_file=r"d:\ScamShield-Pakistan\test_emails\legitimate_email.eml")
meta = a.extract_basic_metadata()
auth = a.check_authentication()
urls = a.extract_urls()
atts = a.extract_attachments()
patterns = a.detect_phishing_patterns()
spoof = a.detect_spoofing()
hdr = a.detect_header_anomalies()

print(f"From: {meta.get('From')}")
print(f"Subject: {meta.get('Subject')}")
print(f"Auth: spf={auth.get('spf')}, dkim={auth.get('dkim')}, dmarc={auth.get('dmarc')}, suspicious={auth.get('is_suspicious')}")
print(f"Spoof: is_spoofed={spoof.get('is_spoofed')}, findings={len(spoof.get('findings', []))}")
for f in spoof.get('findings', []):
    print(f"  -> {f.get('type')}: {f.get('message')} (sev={f.get('severity')})")
print(f"Patterns: urgency={patterns.get('urgency')}, credential={patterns.get('credential')}, impersonation={patterns.get('impersonation')}")
print(f"Header anomalies: {hdr.get('anomalies')}")
print(f"URLs: {len(urls)}")

result = a.calculate_risk_score(
    auth=auth, urls=urls, attachments=atts, patterns=patterns,
    spoofing=spoof, header_anomalies=hdr,
)
print(f"\nSCORE: {result['score']} ({result['level']})")
print("Breakdown:")
for k, v in result['breakdown'].items():
    print(f"  {k}: +{v[0]}pts  {v[1]}")
