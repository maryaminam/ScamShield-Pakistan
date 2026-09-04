import sys
from email_forensic_analyzer import EmailForensicAnalyzer

def mock_score(path):
    print(f"\n[{path}] (Mocking Old Domain, Clean Auth, No Hard Indicators)")
    try:
        analyzer = EmailForensicAnalyzer(eml_file=path)
        auth = analyzer.check_authentication()
        urls = analyzer.extract_urls()
        atts = analyzer.extract_attachments()
        patterns = analyzer.detect_phishing_patterns()
        spoof = analyzer.detect_spoofing()
        hdr = analyzer.detect_header_anomalies()
        
        # Override data to ensure no hard indicators & old domain
        # Auth: make it completely clean
        auth_clean = {
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "compauth": "pass", "is_suspicious": False,
            "findings": []
        }
        
        # Domain rep: Verified old
        domain_rep_old = {
            "is_young": False,
            "domain_age_days": 1500,
            "error": None
        }
        
        # We need to make sure URLs and Attachments have no hard indicators
        for u in urls:
            u["mismatch"] = False
            u["is_homograph"] = False
            if "path_indicators" in u:
                u["path_indicators"]["path_brand_match"] = False
                
        for a in atts:
            a["risky"] = False
            a["brand_mismatch"] = False
            
        spoof_clean = {"is_spoofed": False, "findings": [], "severity": "low"}
        
        score_dict = analyzer.calculate_risk_score(
            auth=auth_clean,
            urls=urls,
            attachments=atts,
            patterns=patterns,
            spoofing=spoof_clean,
            header_anomalies=hdr,
            domain_rep=domain_rep_old
        )
        print(f"Score: {score_dict['score']} ({score_dict['level']})")
        for key, val in score_dict["breakdown"].items():
            print(f"  - {key}: {val[0]} pts ({val[1]})")
    except Exception as e:
        print(f"Error: {e}")

mock_score("test_emails/alibaba_legitimate.eml")
mock_score("test_emails/legitimate_email.eml")
mock_score("test_emails/adversarial.eml")
