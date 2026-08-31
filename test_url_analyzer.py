import os
import sys

# Inject dummy API keys for test
os.environ["VT_API"] = "dummy_vt"
os.environ["ABUSEIPDB_API"] = "dummy_abuse"

from web_app import _analyze_email, _analyze_url

# Test 1: URL Mismatches & Redirects
raw = """From: attacker@evil.com
Subject: Test email

Hello, here is a link: http://bit.ly/1234
And a homograph: http://paypa1.com/login
And punycode: http://xn--b1a.com
"""

print("Running test...")
result = _analyze_email(raw)
print("Risk Level:", result["threat_intel"]["risk"]["level"])
print("Score:", result["threat_intel"]["risk"]["score"])
print("Breakdown:")
for k, v in result["threat_intel"]["risk"]["breakdown"].items():
    print(f"  {k}: {v}")

print("URLs:")
for u in result["urls"]:
    print(f"  {u}")
