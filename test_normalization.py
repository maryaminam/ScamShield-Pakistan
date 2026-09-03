"""Test normalization, brand-mismatch, and regression on all .eml files."""
import os, sys, unicodedata
sys.path.insert(0, os.path.dirname(__file__))

from email_forensic_analyzer import EmailForensicAnalyzer, strip_combining_marks, _BRAND_DOMAINS

# ── 1. Unit-test strip_combining_marks ──────────────────────────────────
print("=" * 60)
print("TEST 1: strip_combining_marks()")
print("=" * 60)

cases = [
    ("Amazon", "Amazon"),
    ("A\u0308mazon", "Amazon"),        # A + combining diaeresis -> A
    ("PayPa\u0301l", "PayPal"),        # combining accent on 'a'
    ("Microsoft", "Microsoft"),
    ("", ""),
    ("Hello World", "Hello World"),
    # Syriac combining mark (U+071F) used in real obfuscation
    ("A\u071fm\u071fazon", "Amazon"),
]
ok = True
for inp, expected in cases:
    result = strip_combining_marks(inp)
    status = "OK" if result == expected else "FAIL"
    if status == "FAIL":
        ok = False
    print(f"  {status}: strip_combining_marks({inp!r}) = {result!r}  (expected {expected!r})")
print(f"  All passed: {ok}")

# ── 2. Regression: analyze all .eml files ────────────────────────────────
print()
print("=" * 60)
print("TEST 2: Regression on all .eml files")
print("=" * 60)

eml_dir = os.path.join(os.path.dirname(__file__), "test_emails")
eml_files = sorted(f for f in os.listdir(eml_dir) if f.endswith(".eml"))
errors = 0
for fname in eml_files:
    path = os.path.join(eml_dir, fname)
    try:
        analyzer = EmailForensicAnalyzer(raw_text=open(path, encoding="utf-8", errors="replace").read())
        meta = analyzer.extract_basic_metadata()
        auth = analyzer.check_authentication()
        urls = analyzer.extract_urls()
        attachments = analyzer.extract_attachments()
        spoof = analyzer.detect_spoofing()
        patterns = analyzer.detect_phishing_patterns()
        risk = analyzer.calculate_risk_score(
            auth=auth, urls=urls, attachments=attachments,
            patterns=patterns, spoofing=spoof,
        )
        # Verify brand_mismatch key exists in every attachment
        for att in attachments:
            assert "brand_mismatch" in att, f"Missing brand_mismatch key in {fname}/{att['filename']}"
        print(f"  OK  {fname:45s}  Risk={risk['level']:8s} ({risk['score']:3d}/100)  "
              f"Attachments={len(attachments)}  URLs={len(urls)}")
    except Exception as exc:
        errors += 1
        print(f"  FAIL {fname}: {exc}")

print(f"  Files tested: {len(eml_files)}, Errors: {errors}")

# ── 3. Brand-mismatch detection in attachments ──────────────────────────
print()
print("=" * 60)
print("TEST 3: Attachment brand-mismatch field")
print("=" * 60)

# Craft a synthetic email with a PayPal-branded attachment from a non-PayPal domain
synthetic = """From: scammer@evil-domain.com
To: victim@example.com
Subject: Your PayPal account
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Please review the attached PayPal invoice.

--boundary123
Content-Type: application/pdf; name="PayPal-Invoice-2024.pdf"
Content-Disposition: attachment; filename="PayPal-Invoice-2024.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKMSAwIG9iago=
--boundary123--
"""

analyzer = EmailForensicAnalyzer(raw_text=synthetic)
attachments = analyzer.extract_attachments()
for att in attachments:
    bm = att.get("brand_mismatch", False)
    print(f"  {att['filename']:40s}  risky={att['risky']}  brand_mismatch={bm}")
    if "paypal" in att["filename"].lower() and bm:
        print("  -> CORRECTLY flagged brand mismatch (PayPal attachment from evil-domain.com)")
    elif "paypal" in att["filename"].lower() and not bm:
        print("  -> FAILED to flag brand mismatch!")

# Test: same attachment from a legitimate PayPal domain
legit = synthetic.replace("scammer@evil-domain.com", "noreply@paypal.com")
analyzer2 = EmailForensicAnalyzer(raw_text=legit)
attachments2 = analyzer2.extract_attachments()
for att in attachments2:
    bm = att.get("brand_mismatch", False)
    print(f"  {att['filename']:40s}  risky={att['risky']}  brand_mismatch={bm}")
    if "paypal" in att["filename"].lower() and not bm:
        print("  -> CORRECTLY no brand mismatch (legitimate PayPal sender)")
    elif "paypal" in att["filename"].lower() and bm:
        print("  -> FALSE POSITIVE on legitimate sender!")

# ── 4. Normalization defeats combining-diacritic obfuscation ─────────────
print()
print("=" * 60)
print("TEST 4: Combining-diacritic obfuscation in display name")
print("=" * 60)

# Display name with combining marks hiding "Amazon"
obfuscated = """From: "A\u0308m\u0308a\u0308z\u0308o\u0308n\u0308 Support" <scammer@evil-domain.com>
To: victim@example.com
Subject: Your account is locked

Please verify your account immediately.
"""
analyzer3 = EmailForensicAnalyzer(raw_text=obfuscated)
spoof = analyzer3.detect_spoofing()
patterns = analyzer3.detect_phishing_patterns()
brand_findings = [f for f in spoof["findings"] if f["type"] == "brand_impersonation"]
imp_matches = patterns.get("impersonation", [])
print(f"  Spoofing findings: {len(spoof['findings'])}")
for f in brand_findings:
    print(f"    -> {f['message']}")
print(f"  Impersonation patterns: {imp_matches}")
if brand_findings:
    print("  -> CORRECTLY detected brand impersonation despite combining-diacritic obfuscation")
else:
    print("  -> FAILED to detect obfuscated brand name!")

if "amazon" in [p.lower() for p in imp_matches]:
    print("  -> CORRECTLY detected 'amazon' impersonation keyword despite obfuscation")
else:
    print("  -> FAILED to detect obfuscated impersonation keyword!")

print()
print("All tests complete.")
