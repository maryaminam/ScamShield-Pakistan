import sys
from email_forensic_analyzer import EmailForensicAnalyzer

def print_breakdown(path):
    print(f"\n[{path}]")
    try:
        analyzer = EmailForensicAnalyzer(eml_file=path)
        score_dict = analyzer.calculate_risk_score()
        print(f"Score: {score_dict['score']} ({score_dict['level']})")
        for key, val in score_dict["breakdown"].items():
            print(f"  - {key}: {val[0]} pts ({val[1]})")
    except Exception as e:
        print(f"Error: {e}")

print_breakdown("test_emails/phishing2.eml")
