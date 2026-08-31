import ipaddress
import socket
import requests
import unicodedata
import base64
import time
from urllib.parse import urlparse
from email_forensic_analyzer import EmailForensicAnalyzer, _BRAND_DOMAINS

_VT_URL_CACHE: dict[str, dict] = {}

def check_url_virustotal(url: str, api_key: str) -> dict:
    """Query VirusTotal for a full URL scan."""
    cache_entry = _VT_URL_CACHE.get(url)
    if cache_entry and time.time() - cache_entry["timestamp"] < 3600:
        return cache_entry["result"]
        
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        resp = requests.get(api_url, headers={"x-apikey": api_key}, timeout=5.0)
        if resp.status_code == 404:
            res = {"url": url, "detections": 0, "is_malicious": False}
            _VT_URL_CACHE[url] = {"timestamp": time.time(), "result": res}
            return res
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
        res = {"url": url, "detections": detections, "is_malicious": detections > 0}
        _VT_URL_CACHE[url] = {"timestamp": time.time(), "result": res}
        return res
    except requests.RequestException as exc:
        return {"url": url, "error": f"VirusTotal request failed: {exc}"}

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

def resolve_url(url: str) -> tuple[str, str, str]:
    """Follow redirects to find the final URL and domain.
    Returns (final_url, final_domain, status)
    """
    try:
        resp = requests.head(url, allow_redirects=True, timeout=5.0)
        final_url = resp.url
        final_domain = urlparse(final_url).netloc.lower()
        if final_url != url:
            return final_url, final_domain, "redirected"
        return final_url, final_domain, "ok"
    except requests.Timeout:
        return url, urlparse(url).netloc.lower(), "timeout"
    except requests.RequestException:
        return url, urlparse(url).netloc.lower(), "error"

def is_homograph(domain: str) -> bool:
    """Check if domain uses punycode or is a common homoglyph of a known brand."""
    try:
        if domain.encode('idna').startswith(b'xn--'):
            return True
    except UnicodeError:
        return True
        
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
        
    try:
        from Levenshtein import distance
    except ImportError:
        try:
            from rapidfuzz.distance.Levenshtein import distance
        except ImportError:
            distance = None
            
    if distance:
        label = _registrable_domain(domain).split(".")[0]
        for brand, legitimate in _BRAND_DOMAINS.items():
            if len(brand) >= 4 and 1 <= distance(label, brand) <= 2:
                if not any(domain == d or domain.endswith("." + d) for d in legitimate):
                    return True

    return False

def analyze_standalone_url(raw_url: str, vt_api_key: str | None = None, abuseipdb_api_key: str | None = None) -> dict:
    candidate = raw_url.strip()
    candidate_parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
    original_hostname = (candidate_parsed.hostname or "").lower().rstrip(".")

    res_url, res_domain, status = resolve_url(candidate if "://" in candidate else f"http://{candidate}")
    parsed = urlparse(res_url)
    hostname = res_domain
    if not hostname:
        raise ValueError("Enter a valid URL with a hostname.")
    indicators: list[dict] = []
    score = 0
    
    if status == "redirected":
        indicators.append(_url_indicator(f"URL redirected. Final destination: {hostname}", "medium", 15))
        score += 15
    elif status == "timeout":
        indicators.append(_url_indicator("URL timed out during resolution (suspicious shortener/host)", "low", 10))
        score += 10
    elif status == "error":
        indicators.append(_url_indicator("URL connection failed or was refused", "low", 10))
        score += 10
    
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
        vt = check_url_virustotal(raw_url, vt_api_key)
        if not vt.get("error") and vt.get("is_malicious"):
            indicators.append(_url_indicator(f"known_malicious: URL is flagged by {vt.get('detections')} VirusTotal engines", "high", 100))
            score += 100
    
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
