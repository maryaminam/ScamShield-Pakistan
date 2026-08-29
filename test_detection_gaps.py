"""Smoke test for the four detection-gap fixes."""

import requests

from email_forensic_analyzer import EmailForensicAnalyzer

# Synthetic email exercising all four new signals.
RAW_EMAIL = """\
From: =?UTF-8?Q?Atendimento_ao_Cliente?= <notifications@uorak.com>
To: victim@example.com
Subject: =?UTF-8?Q?Atualize_seus_dados_agora?=
Date: Sat, 29 Aug 2026 08:00:00 +0000
Message-ID: <abc123@uorak.com>
Reply-To: noreply@uorak.com
Return-Path: <bounce@uorak.com>
Authentication-Results: spf=pass (sender IP is 1.2.3.4)
  smtp.mailfrom=uorak.com; dkim=pass (signature was verified)
  header.d=someotherdomain.com header.s=selector1;
  dmarc=none action=none header.from=uorak.com;
  compauth=fail reason=001
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Prezado cliente, atualize seus dados imediatamente clicando no link abaixo:</p>
<a href="https://login6.conteudo-protegido.one/atualizar">Clique aqui para atualizar</a>
<p>Se voce nao atualizar, sua conta sera suspensa.</p>
</body></html>
"""


def test_gap1_compauth_parsing():
    """GAP 1: compauth and compauth_reason must be extracted."""
    analyzer = EmailForensicAnalyzer(raw_text=RAW_EMAIL)
    auth = analyzer.check_authentication()
    assert auth["compauth"] == "fail", f"Expected compauth='fail', got {auth['compauth']!r}"
    assert auth["compauth_reason"] == "001", f"Expected reason='001', got {auth['compauth_reason']!r}"
    assert auth["is_suspicious"] is True, "compauth=fail should mark as suspicious"
    # SPF/DKIM passed, so traditional auth should not separately flag
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "pass"
    print("  [PASS] GAP 1: compauth parsed correctly")


def test_gap2_header_anomaly_scoring():
    """GAP 2: DKIM d= mismatch should be detected and scored."""
    analyzer = EmailForensicAnalyzer(raw_text=RAW_EMAIL)
    anomalies = analyzer.detect_header_anomalies()
    assert anomalies["is_anomalous"], "Expected anomalies to be flagged"
    dkim_msgs = [a for a in anomalies["anomalies"] if "DKIM signing domain" in a]
    assert len(dkim_msgs) > 0, "Expected DKIM signing domain mismatch anomaly"
    print("  [PASS] GAP 2: DKIM signing domain mismatch detected")


def test_gap3_url_domain_reputation():
    """GAP 3: check_url_domain_reputation returns correctly shaped list."""
    analyzer = EmailForensicAnalyzer(raw_text=RAW_EMAIL)
    urls = analyzer.extract_urls()
    assert len(urls) > 0, "Expected at least one URL"
    reps = analyzer.check_url_domain_reputation(urls=urls)
    assert isinstance(reps, list), "Expected a list"
    # Should have checked the linked domain (not the sender domain)
    domains_checked = [r["domain"] for r in reps]
    print(f"  URL domains checked: {domains_checked}")
    for r in reps:
        assert "domain" in r and "is_young" in r, f"Missing keys in {r}"
    print("  [PASS] GAP 3: check_url_domain_reputation returns correct shape")


def test_combined_risk_score():
    """All four gaps combined should produce a score well above Low (>25)."""
    analyzer = EmailForensicAnalyzer(raw_text=RAW_EMAIL)
    auth = analyzer.check_authentication()
    urls = analyzer.extract_urls()
    attachments = analyzer.extract_attachments()
    spoofing = analyzer.detect_spoofing()
    anomalies = analyzer.detect_header_anomalies()
    patterns = analyzer.detect_phishing_patterns()

    # URL domain reps - may timeout for whois, that's OK
    url_reps = analyzer.check_url_domain_reputation(urls=urls)

    risk = analyzer.calculate_risk_score(
        auth=auth, urls=urls, attachments=attachments,
        patterns=patterns, spoofing=spoofing,
        header_anomalies=anomalies,
        url_domain_reps=url_reps,
    )
    score = risk["score"]
    level = risk["level"]
    print(f"  Score: {score}/100 — Level: {level}")
    print(f"  Breakdown: {risk['breakdown']}")
    assert score >= 25, f"Expected score >= 25 (Medium+), got {score}"
    assert level != "Low", f"Expected level != Low, got {level}"
    print(f"  [PASS] Combined score is {score} ({level}) — no longer Low")


def test_abuseipdb_invalid_key_reports_clear_error(monkeypatch):
    """A bad or expired AbuseIPDB key should produce a clean error message."""

    class FakeResponse:
        def raise_for_status(self):
            raise requests.exceptions.HTTPError("401 Client Error: Unauthorized")

    monkeypatch.setattr("email_forensic_analyzer.requests.get", lambda *args, **kwargs: FakeResponse())

    result = EmailForensicAnalyzer(raw_text=RAW_EMAIL).check_ip_abuse("8.8.8.8", api_key="bad-key")
    assert "Unauthorized" in result["error"], result
    assert "invalid or expired" in result["error"].lower(), result
    print("  [PASS] AbuseIPDB invalid key is surfaced clearly")


if __name__ == "__main__":
    print("=== Detection Gap Tests ===")
    test_gap1_compauth_parsing()
    test_gap2_header_anomaly_scoring()
    test_gap3_url_domain_reputation()
    test_combined_risk_score()
    print("\n=== All tests passed ===")
