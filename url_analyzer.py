import ipaddress
import socket
import requests
import unicodedata
from urllib.parse import urlparse
from email_forensic_analyzer import EmailForensicAnalyzer, _BRAND_DOMAINS

_SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "zip", "click", "site", "online", "live", "date", "club",
    "vip", "work", "beauty", "icu", "shop", "cyou", "today", "gq", "ml", "cf",
    "tk", "ga", "men", "loan", "win", "racing", "stream",
})

def _registrable_domain(hostname: str) -> str:
    """A conservative two-label registrable-domain approximation for heuristics."""
    labels = hostname.lower().strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname

def _url_indicator(flag: str, severity: str, points: int) -> dict:
    return {"flag": flag, "severity": severity, "points": points}

def resolve_url(url: str) -> tuple[str, str]:
    """Follow redirects to find the final URL and domain."""
    try:
        resp = requests.head(url, allow_redirects=True, timeout=2.0)
        if resp.url != url:
            return resp.url, urlparse(resp.url).netloc.lower()
    except requests.RequestException:
        pass
    return url, urlparse(url).netloc.lower()

def is_homograph(domain: str) -> bool:
    """Check if domain uses punycode or is a common homoglyph of a known brand."""
    if domain.startswith("xn--"):
        return True
    domain_ascii = unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode("ascii")
    if not domain_ascii or len(domain_ascii) < 3:
        return False
    from email_forensic_analyzer import _BRAND_DOMAINS
    def resembles_brand(test_str: str) -> bool:
        norm = test_str.replace("1", "l").replace("0", "o").replace("rn", "m")
        for b in _BRAND_DOMAINS:
            if b in norm and b not in domain:
                return True
        return False
    # Check if the domain itself mimics a brand
    if resembles_brand(domain):
        return True
    return False

def analyze_standalone_url(raw_url: str, vt_api_key: str | None = None, abuseipdb_api_key: str | None = None) -> dict:
    candidate = raw_url.strip()
    candidate_parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
    original_hostname = (candidate_parsed.hostname or "").lower().rstrip(".")

    res_url, res_domain = resolve_url(candidate if "://" in candidate else f"http://{candidate}")
    parsed = urlparse(res_url)
    hostname = res_domain
    if not hostname:
        raise ValueError("Enter a valid URL with a hostname.")
    indicators: list[dict] = []
    score = 0
    
    try:
        ipaddress.ip_address(hostname)
        indicators.append(_url_indicator("URL uses a raw IP address instead of a domain", "high", 30))
        score += 30
        is_ip = True
    except ValueError:
        is_ip = False
        
    if parsed.scheme.lower() != "https":
        indicators.append(_url_indicator("URL does not use HTTPS", "medium", 15))
        score += 15
        
    labels = hostname.split(".")
    if not is_ip and labels and labels[-1] in _SUSPICIOUS_TLDS:
        indicators.append(_url_indicator(f"Uncommon or abuse-prone .{labels[-1]} TLD", "medium", 15))
        score += 15
        
    if not is_ip and len(labels) - 2 > 3:
        indicators.append(_url_indicator("Excessive subdomain depth", "medium", 10))
        score += 10
        
    registrable = _registrable_domain(hostname)
    orig_registrable = _registrable_domain(original_hostname)
    
    is_hg_orig = is_homograph(original_hostname)
    is_hg_res = is_homograph(hostname)
    
    if is_hg_orig or is_hg_res:
        bad_domain = original_hostname if is_hg_orig else hostname
        indicators.append(_url_indicator(f"Domain '{bad_domain}' uses punycode or is a misspelled variant of a well-known brand", "high", 60))
        score += 60
    else:
        brand_hit = False
        for brand, legitimate_domains in _BRAND_DOMAINS.items():
            if brand in original_hostname and not any(orig_registrable == domain or orig_registrable.endswith(f".{domain}") for domain in legitimate_domains):
                indicators.append(_url_indicator(f"Brand keyword '{brand}' appears on a non-official domain ({original_hostname})", "high", 25))
                score += 25
                brand_hit = True
                break
        if not brand_hit:
            for brand, legitimate_domains in _BRAND_DOMAINS.items():
                if brand in hostname and not any(registrable == domain or registrable.endswith(f".{domain}") for domain in legitimate_domains):
                    indicators.append(_url_indicator(f"Brand keyword '{brand}' appears on a non-official domain ({hostname})", "high", 25))
                    score += 25
                    break

    # Doing WHOIS programmatically instead of creating an email analyzer instance.
    synthetic = f"From: test@{hostname}\n\n"
    analyzer = EmailForensicAnalyzer(raw_text=synthetic)
    # the check_domain_reputation method uses Whois inside EmailForensicAnalyzer.
    domain_rep_raw = analyzer.check_domain_reputation(hostname)
    domain_info = {
        "registrar": domain_rep_raw.get("registrar"), 
        "creation_date": domain_rep_raw.get("creation_date"),
        "domain_age_days": domain_rep_raw.get("domain_age_days"), 
        "is_young": bool(domain_rep_raw.get("is_young"))
    }
    if domain_info["is_young"]:
        indicators.append(_url_indicator("Domain was registered recently", "high", 25))
        score += 25
        
    score = min(score, 100)
    
    if vt_api_key:
        vt = EmailForensicAnalyzer.check_domain_virustotal(hostname, vt_api_key)
        if not vt.get("error") and vt.get("is_malicious"):
            indicators.append(_url_indicator("Domain is flagged by VirusTotal as malicious", "high", 50))
            score += 50
    
    if abuseipdb_api_key:
        try:
            ip = socket.gethostbyname(hostname)
            abuse = analyzer.check_ip_abuse(ip, abuseipdb_api_key)
            if not abuse.get("error") and abuse.get("is_flagged"):
                indicators.append(_url_indicator("IP address is flagged by AbuseIPDB", "high", 30))
                score += 30
        except OSError:
            pass

    score = min(score, 100)
    level = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    recommendation = ("Avoid visiting this URL and report it to security staff." if level in {"Critical", "High"}
                      else "Verify the destination independently before entering data." if level == "Medium"
                      else "No high-risk URL indicators were found; use normal caution.")
                      
    return {
        "url": raw_url, 
        "domain": hostname, 
        "risk_score": score, 
        "threat_level": level,
        "domain_info": domain_info, 
        "indicators": indicators, 
        "recommendation": recommendation
    }
