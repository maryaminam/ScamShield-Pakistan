import os
import glob
from email_forensic_analyzer import EmailForensicAnalyzer

print("Testing adversarial email...")
try:
    analyzer = EmailForensicAnalyzer(eml_file="test_emails/adversarial.eml")
    score_dict = analyzer.calculate_risk_score()
    print(f"Adversarial Score: {score_dict['score']} ({score_dict['level']})")
    print(score_dict["breakdown"])
except Exception as e:
    print(f"Error checking adversarial: {e}")

print("Testing alibaba_legitimate.eml...")
try:
    analyzer = EmailForensicAnalyzer(eml_file="test_emails/alibaba_legitimate.eml")
    score_dict = analyzer.calculate_risk_score()
    print(f"Alibaba Score: {score_dict['score']} ({score_dict['level']})")
    print(score_dict["breakdown"])
except Exception as e:
    print(f"Error checking alibaba: {e}")

emails = glob.glob("test_emails/*.eml")
for path in emails:
    if "alibaba" in path or "adversarial" in path:
        continue
    try:
        analyzer = EmailForensicAnalyzer(eml_file=path)
        score_dict = analyzer.calculate_risk_score()
        print(f"{path}: Score: {score_dict['score']} ({score_dict['level']})")
    except Exception as e:
        pass
