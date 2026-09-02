"""Email Forensic Analyzer - header parsing, metadata extraction, routing,
authentication, geolocation, URL/attachment scanning, and domain reputation."""

import email
import email.policy
import email.utils
import hashlib
import ipaddress
import re
import socket
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup

_GEOLOCATION_API = "http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as"
_API_TIMEOUT = 5  # seconds

# Regex patterns for extracting fields from Received headers
_IP_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"          # IPv4
    r"|"
    r"\[([0-9a-fA-F:]+)\]"                                  # bracketed IPv6
)
_FROM_DOMAIN_RE = re.compile(r"from\s+([\w.\-]+)", re.IGNORECASE)
_BY_DOMAIN_RE = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
_TIMESTAMP_RE = re.compile(r";\s*(.+)$")

# Regex patterns for Authentication-Results parsing.
# Matches e.g. "spf=pass", "dkim=fail (reason)", "dmarc=softfail"
_SPF_RESULT_RE = re.compile(r"\bspf\s*=\s*(\w+)", re.IGNORECASE)
_DKIM_RESULT_RE = re.compile(r"\bdkim\s*=\s*(\w+)", re.IGNORECASE)
_DMARC_RESULT_RE = re.compile(r"\bdmarc\s*=\s*(\w+)", re.IGNORECASE)
_COMPAUTH_RESULT_RE = re.compile(r"\bcompauth\s*=\s*(\w+)", re.IGNORECASE)
_COMPAUTH_REASON_RE = re.compile(r"\breason\s*=\s*(\w+)", re.IGNORECASE)

# Received-SPF fallback: "Received-SPF: pass ..." or "Received-SPF: softfail ..."
_RECEIVED_SPF_RE = re.compile(r"^\s*(\w+)", re.IGNORECASE)

# Statuses that indicate a problem.
_SUSPICIOUS_STATUSES = {"fail", "softfail"}

# URL extraction from plain text bodies.
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# File extensions commonly abused in phishing attachments.
_RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".msi",
    ".hta", ".wsf", ".com", ".pif", ".reg", ".docm", ".xlsm", ".pptm",
    ".iso", ".img", ".zip", ".rar", ".7z", ".cab",
}

# Domain age threshold (days). Domains younger than this are flagged.
_YOUNG_DOMAIN_DAYS = 30

# AbuseIPDB API endpoint.
_ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"

# VirusTotal API endpoint (v3).
_VT_API = "https://www.virustotal.com/api/v3/files/{hash}"
_VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/{domain}"

# DNS resolver timeout (seconds). DNS is enrichment, so it should never hold
# up the core forensic verdict for several seconds per record.
_DNS_TIMEOUT = 1.5
_WHOIS_TIMEOUT_SECONDS = 2.5

# ── Phishing pattern detection ──────────────────────────────────────
_URGENCY_PATTERNS = re.compile(
    r"\b("
    r"urgent|immediately|act now|right away|within \d+ hours?"
    r"|suspend|deactivat|terminat|locked|disabled|compromised"
    r"|verify your|confirm your|update your|validate your"
    r"|unusual activity|unauthorized|security alert|suspicious"
    r"|click here|click below|click immediately"
    r"|final warning|last chance|expire|expiring"
    r")\b",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERNS = re.compile(
    r"\b("
    r"password|login|credential|social security|ssn|credit card"
    r"|bank account|routing number|pin number|cvv"
    r"|enter your|provide your|submit your|send your"
    r")\b",
    re.IGNORECASE,
)
_IMPERSONATION_PATTERNS = re.compile(
    r"\b("
    r"paypal|apple|microsoft|google|amazon|netflix|facebook"
    r"|instagram|whatsapp|bank of america|wells fargo|chase"
    r"|irs|hmrc|tax refund|customs|fedex|ups|dhl"
    r"|helpdesk|it department|support team|admin team"
    r")\b",
    re.IGNORECASE,
)

# X-Headers of forensic interest.
_FORENSIC_X_HEADERS = [
    "X-Mailer",
    "X-Originating-IP",
    "X-Spam-Status",
    "X-Spam-Score",
    "X-Spam-Flag",
    "X-Forefront-Antispam-Report",
    "X-Microsoft-Antispam",
    "X-Google-DKIM-Signature",
    "X-Received",
    "X-Original-To",
    "X-Envelope-From",
    "X-Priority",
]

# Maximum plausible seconds between two consecutive Received hops.
# Anything beyond this is flagged as suspicious (4 hours).
_MAX_HOP_DELTA_SECONDS = 4 * 3600

# Risk-score weights (0–100 total budget).
_WEIGHTS = {
    "auth_fail": 22,       # any SPF/DKIM/DMARC fail or softfail
    "spoofing": 20,        # display-name / Reply-To / Return-Path spoofing
    "url_mismatch": 18,    # display/href domain mismatch
    "risky_attachment": 13, # dangerous file extension
    "young_domain": 12,    # sender domain < 30 days old
    "abuse_ip": 8,         # originating IP flagged on AbuseIPDB
    "urgency_lang": 20,     # urgency phrases in subject/body
    "credential_lang": 40,  # credential-harvesting phrases
    "impersonation": 10,    # brand impersonation keywords
    "compauth_fail": 25,    # Microsoft alignment check failed — domain shown
                             # to user doesn't match authenticated sending domain
    "header_anomaly": 15,   # From/Reply-To/Return-Path/DKIM-d= domain mismatches
    "young_url_domain": 14, # a link in the email body points to a very
                             # recently registered domain
    "homograph_domain": 25, # link domain visually mimics a known brand or uses punycode
    "vt_url_malicious": 25,  # VirusTotal flagged a link domain
    "abuseip_url": 20,       # AbuseIPDB flagged the IP associated with a link domain
}

# Brand → set of legitimate sender domain suffixes. Used by detect_spoofing()
# to flag display names that impersonate a brand from a domain not on its list.
_BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal-mail.com", "paypal.de"},
    "microsoft": {"microsoft.com", "outlook.com", "office365.com", "office.com",
                  "live.com", "hotmail.com", "azure.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com", "me.com", "mac.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "aol": {"aol.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com",
               "amazon.in", "amazon.ca", "aws.amazon.com"},
    "netflix": {"netflix.com", "mailer.netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "mail.instagram.com"},
    "whatsapp": {"whatsapp.com", "support.whatsapp.com"},
    "linkedin": {"linkedin.com", "linkedinmail.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "github": {"github.com", "githubapp.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "irs": {"irs.gov"},
    "hmrc": {"hmrc.gov.uk", "tax.service.gov.uk"},
    "chase": {"chase.com", "jpmorgan.com"},
    "wells fargo": {"wellsfargo.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    # --- Cryptocurrency exchanges ---
    "binance": {"binance.com", "binance.info", "binance.us"},
    "coinbase": {"coinbase.com"},
    "kraken": {"kraken.com"},
    "kucoin": {"kucoin.com"},
    "bybit": {"bybit.com"},
    "okx": {"okx.com"},
    # --- Pakistani banks, fintech & government services ---
    "easypaisa": {"easypaisa.com.pk", "telenor.com.pk"},
    "jazzcash": {"jazzcash.com.pk", "jazz.com.pk"},
    "hbl": {"hbl.com", "hblpay.com.pk"},
    "meezan bank": {"meezanbank.com"},
    "ubl": {"ubldigital.com", "ubl.com.pk"},
    "bank alfalah": {"bankalfalah.com"},
    "mcb": {"mcb.com.pk"},
    "allied bank": {"abl.com", "abl.com.pk"},
    "nayapay": {"nayapay.com"},
    "sadapay": {"sadapay.pk"},
    "state bank of pakistan": {"sbp.org.pk"},
    "fbr": {"fbr.gov.pk"},
    "nadra": {"nadra.gov.pk"},
}

# Free webmail providers — corporate-sounding display names from these are
# almost always phishing.
_FREE_MAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "hotmail.com", "outlook.com", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "tutanota.com", "gmx.com", "gmx.de", "yandex.com", "yandex.ru",
    "mail.com", "zoho.com", "fastmail.com", "163.com", "qq.com",
}

# Display-name terms that imply a corporate/official sender — suspicious from
# a free webmail provider.
_CORPORATE_DISPLAY_TERMS = re.compile(
    r"\b(support|helpdesk|help\s*desk|service|services|admin|administrator"
    r"|security|account|accounts|billing|payroll|hr|human\s*resources"
    r"|it\s*(team|department|support|admin)|tech\s*support|customer\s*(care|service)"
    r"|notification|noreply|no-reply|alerts?|team|department"
    r"|ceo|cfo|cto|director|manager)\b",
    re.IGNORECASE,
)

# Tokens of length ≥ 2 made of letters (incl. Latin-1 supplement / Latin-Extended).
# Used to split a display name like "Dr. José A. Smith-Jones" into name parts.
_NAME_TOKEN_RE = re.compile(r"[A-Za-zÀ-ɏ]{2,}")

# Honorifics, particles, and stop-words to ignore when comparing display names
# against email local-parts. Anything in this set is dropped before matching.
_NAME_NOISE_TOKENS = frozenset({
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "sir", "madam", "rev",
    "the", "and", "of", "via", "from", "der", "den", "van", "von", "de",
    "la", "le", "el", "al", "bin", "ibn", "abu",
})

# Minimum token length required for a "substring inside local-part" match.
# Anything shorter (e.g. "li", "an") is rejected to avoid coincidental hits.
_NAME_TOKEN_MIN_MATCH_LEN = 3


class EmailForensicAnalyzer:
    """Parses raw .eml files or raw header text and extracts forensic metadata."""

    def __init__(self, eml_file: str | None = None, raw_text: str | None = None):
        """Initialize the analyzer from an .eml file path or raw email text.

        Args:
            eml_file: Path to a .eml file on disk.
            raw_text: Raw email content as a string.

        Raises:
            FileNotFoundError: If eml_file does not exist.
            ValueError: If neither eml_file nor raw_text is provided.
        """
        if eml_file is None and raw_text is None:
            raise ValueError("Provide either 'eml_file' or 'raw_text'.")

        if eml_file is not None:
            path = Path(eml_file)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {eml_file}")
            raw_text = path.read_text(encoding="utf-8", errors="replace")

        self.msg = email.message_from_string(raw_text, policy=email.policy.default)

    def extract_basic_metadata(self) -> dict:
        """Extract core email headers useful for forensic investigation.

        Returns:
            A dictionary with the following keys (value is None when the
            header is absent from the message):
                - Message-ID
                - Date
                - From
                - To
                - Subject
                - Return-Path
        """
        headers = [
            "Message-ID",
            "Date",
            "From",
            "To",
            "Subject",
            "Return-Path",
        ]
        return {h: self.msg.get(h) for h in headers}

    # ------------------------------------------------------------------
    # Step 2: Routing-path analysis
    # ------------------------------------------------------------------

    def extract_routing_path(self) -> list[dict]:
        """Parse all ``Received:`` headers into chronological hop-by-hop order.

        Received headers are stored top-to-bottom (newest first) in the
        message.  This method reverses them so index 0 is the *originating*
        hop and the last entry is the final delivery.

        Returns:
            A list of dicts, one per hop, each containing:
                - hop        : 1-based hop number (chronological)
                - from       : sending domain extracted from "from <domain>"
                - by         : receiving server extracted from "by <domain>"
                - ip         : first IP address found in the header (str or None)
                - timestamp  : raw timestamp string after the semicolon (str or None)
        """
        received_headers: list[str] = self.msg.get_all("Received") or []

        # Reverse so the oldest hop comes first (chronological order).
        received_headers = list(reversed(received_headers))

        hops: list[dict] = []
        for idx, raw in enumerate(received_headers, start=1):
            # Collapse folded whitespace into a single line for easier matching.
            header = " ".join(raw.split())

            from_match = _FROM_DOMAIN_RE.search(header)
            by_match = _BY_DOMAIN_RE.search(header)
            ts_match = _TIMESTAMP_RE.search(header)

            # Collect all IPs, pick the first one.
            ip_matches = _IP_RE.findall(header)
            # _IP_RE has two groups (ipv4, ipv6); take whichever matched.
            first_ip = None
            for v4, v6 in ip_matches:
                first_ip = v4 or v6
                break

            hops.append(
                {
                    "hop": idx,
                    "from": from_match.group(1) if from_match else None,
                    "by": by_match.group(1) if by_match else None,
                    "ip": first_ip,
                    "timestamp": ts_match.group(1).strip() if ts_match else None,
                }
            )

        return hops

    @property
    def originating_ip(self) -> str | None:
        """Return the first *public* IP address from the routing path.

        Private / reserved ranges (RFC 1918, loopback, link-local, etc.)
        are skipped.  Returns ``None`` when no public IP is found.
        """
        received_headers: list[str] = self.msg.get_all("Received") or []
        # Walk oldest-first (chronological).
        for raw in reversed(received_headers):
            header = " ".join(raw.split())
            for v4, v6 in _IP_RE.findall(header):
                ip_str = v4 or v6
                try:
                    addr = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                if addr.is_global:
                    return str(addr)
        return None


    # ------------------------------------------------------------------
    # Step 3: Authentication / spoofing detection
    # ------------------------------------------------------------------

    def check_authentication(self) -> dict:
        """Evaluate SPF, DKIM, and DMARC results from the email headers.

        Parsing strategy:
            1. Look for the ``Authentication-Results`` header and extract
               spf=, dkim=, and dmarc= tokens via regex.
            2. If ``Authentication-Results`` is absent, fall back to the
               older ``Received-SPF`` header for the SPF result only.

        Returns:
            A dict with the following keys:
                - spf           : result string (e.g. "pass", "fail") or None
                - dkim          : result string or None
                - dmarc         : result string or None
                - is_suspicious : True if *any* protocol returned "fail"
                                  or "softfail"
        """
        spf: str | None = None
        dkim: str | None = None
        dmarc: str | None = None
        compauth: str | None = None
        compauth_reason: str | None = None

        auth_results = self.msg.get("Authentication-Results")

        if auth_results is not None:
            # Collapse folded whitespace.
            auth_text = " ".join(auth_results.split())

            spf_m = _SPF_RESULT_RE.search(auth_text)
            dkim_m = _DKIM_RESULT_RE.search(auth_text)
            dmarc_m = _DMARC_RESULT_RE.search(auth_text)
            compauth_m = _COMPAUTH_RESULT_RE.search(auth_text)
            compauth_reason_m = _COMPAUTH_REASON_RE.search(auth_text)

            if spf_m:
                spf = spf_m.group(1).lower()
            if dkim_m:
                dkim = dkim_m.group(1).lower()
            if dmarc_m:
                dmarc = dmarc_m.group(1).lower()
            if compauth_m:
                compauth = compauth_m.group(1).lower()
            if compauth_reason_m:
                compauth_reason = compauth_reason_m.group(1)
        else:
            # Fallback: Received-SPF header (provides SPF only).
            received_spf = self.msg.get("Received-SPF")
            if received_spf is not None:
                m = _RECEIVED_SPF_RE.match(received_spf)
                if m:
                    spf = m.group(1).lower()

        results = {r for r in (spf, dkim, dmarc) if r is not None}
        is_suspicious = bool(results & _SUSPICIOUS_STATUSES) or compauth == "fail"

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "compauth": compauth,
            "compauth_reason": compauth_reason,
            "is_suspicious": is_suspicious,
        }


    # ------------------------------------------------------------------
    # Step 4: OSINT – IP geolocation
    # ------------------------------------------------------------------

    @staticmethod
    def geolocate_ip(ip: str) -> dict:
        """Look up geographic and network information for an IP address.

        Uses the free ip-api.com service.  Private / reserved IPs are
        detected locally and never sent to the API.

        Args:
            ip: An IPv4 or IPv6 address string.

        Returns:
            A dict with keys: country, city, isp, asn.
            On error (timeout, rate-limit, bad IP) the dict contains an
            ``error`` key describing what went wrong.
        """
        # --- Validate and check for private/reserved IPs ----------------
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"error": f"Invalid IP address: {ip}"}

        if not addr.is_global:
            return {
                "country": None,
                "city": None,
                "isp": None,
                "asn": None,
                "note": "Internal IP - No Geolocation",
            }

        # --- Query ip-api.com ------------------------------------------
        try:
            resp = requests.get(
                _GEOLOCATION_API.format(ip=ip),
                timeout=_API_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.Timeout:
            return {"error": "Geolocation request timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Unable to reach geolocation API"}
        except requests.exceptions.RequestException as exc:
            return {"error": f"Geolocation request failed: {exc}"}

        if data.get("status") == "fail":
            return {"error": f"API error: {data.get('message', 'unknown')}"}

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
        }


    # ------------------------------------------------------------------
    # Step 5: URL & link extraction
    # ------------------------------------------------------------------



    def extract_urls(self) -> list[dict]:
        """Extract all URLs from the email body and detect display/href mismatches.

        For HTML bodies, each ``<a>`` tag is inspected: if the visible text
        looks like a URL but points to a *different* domain, the link is
        flagged as a mismatch (a common phishing trick).

        Plain-text bodies are scanned with a regex fallback.

        Returns:
            A list of dicts, each containing:
                - url         : the actual href / URL string
                - display_text: visible anchor text (HTML only, else None)
                - domain      : domain extracted from the URL
                - mismatch    : True if display text domain != href domain
        """
        urls: list[dict] = []
        seen: set[str] = set()

        html_body: str | None = None
        plain_body: str | None = None

        # Walk MIME parts to find HTML and plain-text bodies.
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ct = part.get_content_type()
                if ct == "text/html" and html_body is None:
                    html_body = part.get_content()
                elif ct == "text/plain" and plain_body is None:
                    plain_body = part.get_content()
        else:
            ct = self.msg.get_content_type()
            body = self.msg.get_content()
            if ct == "text/html":
                html_body = body
            else:
                plain_body = body

        # Prefer HTML parsing — it gives us display-text mismatch detection.
        if html_body:
            soup = BeautifulSoup(html_body, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if not href.lower().startswith(("http://", "https://")):
                    continue
                if href in seen:
                    continue
                seen.add(href)

                resolved_href, res_domain, _ = resolve_url(href)
                display = tag.get_text(strip=True)

                # Check if display text itself looks like a URL with a
                # different domain (e.g. text says paypal.com, href is evil.com).
                mismatch = False
                if display.startswith(("http://", "https://")):
                    display_domain = urlparse(display).netloc.lower()
                    if display_domain and display_domain != res_domain:
                        mismatch = True

                href_domain = urlparse(href).netloc.lower()

                urls.append({
                    "url": resolved_href,
                    "display_text": display or None,
                    "domain": res_domain,
                    "mismatch": mismatch,
                    "is_homograph": is_homograph(href_domain) or is_homograph(res_domain),
                })

            # Also grab URLs in plain text that aren't inside <a> tags.
            visible_text = soup.get_text()
            for match in _URL_RE.findall(visible_text):
                if match not in seen:
                    seen.add(match)
                    match_domain = urlparse(match).netloc.lower()
                    res_match, res_domain, _ = resolve_url(match)
                    urls.append({
                        "url": res_match,
                        "display_text": None,
                        "domain": res_domain,
                        "mismatch": False,
                        "is_homograph": is_homograph(match_domain) or is_homograph(res_domain),
                    })

        elif plain_body:
            for match in _URL_RE.findall(plain_body):
                if match not in seen:
                    seen.add(match)
                    match_domain = urlparse(match).netloc.lower()
                    res_match, res_domain, _ = resolve_url(match)
                    urls.append({
                        "url": res_match,
                        "display_text": None,
                        "domain": res_domain,
                        "mismatch": False,
                        "is_homograph": is_homograph(match_domain) or is_homograph(res_domain),
                    })

        return urls

    # ------------------------------------------------------------------
    # Step 5: Attachment analysis
    # ------------------------------------------------------------------

    def extract_attachments(self) -> list[dict]:
        """List all attachments with metadata and risk assessment.

        Returns:
            A list of dicts, each containing:
                - filename  : original filename (or "unnamed")
                - mime_type : Content-Type (e.g. "application/pdf")
                - size      : size in bytes
                - md5       : MD5 hex digest
                - sha256    : SHA-256 hex digest
                - risky     : True if the file extension is in _RISKY_EXTENSIONS
        """
        attachments: list[dict] = []

        for part in self.msg.walk():
            disposition = part.get_content_disposition()
            if disposition not in ("attachment", "inline"):
                continue

            filename = part.get_filename() or "unnamed"
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            ext = Path(filename).suffix.lower()

            attachments.append({
                "filename": filename,
                "mime_type": part.get_content_type(),
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "risky": ext in _RISKY_EXTENSIONS,
            })

        return attachments

    # ------------------------------------------------------------------
    # Step 5: Sender domain reputation (WHOIS age check)
    # ------------------------------------------------------------------

    def check_domain_reputation(self, domain: str | None = None) -> dict:
        """WHOIS lookup on the sender domain to assess its age.

        A domain registered very recently (< 30 days) is a strong phishing
        indicator.

        Args:
            domain: Domain to check.  If ``None``, the domain is extracted
                    from the ``From`` header automatically.

        Returns:
            A dict with keys:
                - domain        : the domain that was checked
                - registrar     : registrar name (or None)
                - creation_date : registration date (ISO string or None)
                - domain_age_days: age in days (int or None)
                - is_young      : True if age < _YOUNG_DOMAIN_DAYS
                - error         : present only on failure
        """
        if domain is None:
            from_header = self.msg.get("From") or ""
            # "Name <user@domain>" or plain "user@domain"
            at_pos = from_header.rfind("@")
            if at_pos == -1:
                return {"domain": None, "error": "No domain in From header"}
            domain = from_header[at_pos + 1 :].strip().rstrip(">").lower()

        try:
            # Import lazily to avoid hard failure when optional deps are missing
            # in the currently selected editor environment.
            whois_module = __import__("whois")
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(_WHOIS_TIMEOUT_SECONDS)
            try:
                w = whois_module.whois(domain)
                creation = w.creation_date
                registrar = w.registrar
            finally:
                socket.setdefaulttimeout(original_timeout)
        except Exception:
            w = None
            creation = None
            registrar = None

        if not creation:
            try:
                rdap_resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=_WHOIS_TIMEOUT_SECONDS)
                if rdap_resp.status_code == 200:
                    data = rdap_resp.json()
                    for event in data.get("events", []):
                        if event.get("eventAction") == "registration":
                            d_str = event.get("eventDate", "").replace("Z", "+00:00")
                            creation = datetime.fromisoformat(d_str)
                            break
                    for entity in data.get("entities", []):
                        if "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for prop in vcard[1]:
                                    if prop[0] == "fn":
                                        registrar = prop[3]
                                        break
            except Exception:
                pass

        if isinstance(creation, list):
            creation = creation[0]

        age_days: int | str = "unknown"
        is_young = False
        creation_iso: str | None = None

        if isinstance(creation, datetime):
            creation_iso = creation.isoformat()
            age_days = (datetime.now(timezone.utc) - creation.replace(
                tzinfo=timezone.utc
            )).days
            is_young = age_days < _YOUNG_DOMAIN_DAYS

        return {
            "domain": domain,
            "registrar": registrar or "unknown",
            "creation_date": creation_iso,
            "domain_age_days": age_days,
            "is_young": is_young,
        }

    @staticmethod
    def check_domain_virustotal(domain: str, api_key: str | None = None) -> dict:
        """Query VirusTotal for scan results on a domain."""
        if api_key is None:
            return {"domain": domain, "error": "No VirusTotal API key provided"}
        try:
            resp = requests.get(
                _VT_DOMAIN_API.format(domain=domain),
                headers={"x-apikey": api_key},
                timeout=_API_TIMEOUT,
            )
            if resp.status_code == 404:
                return {"domain": domain, "detections": 0, "is_malicious": False}
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
        except requests.exceptions.RequestException as exc:
            return {"domain": domain, "error": f"VirusTotal request failed: {exc}"}
        
        stats = data.get("last_analysis_stats", {})
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return {
            "domain": domain,
            "detections": detections,
            "is_malicious": detections > 0,
        }

    # ------------------------------------------------------------------
    # URL-domain reputation (WHOIS/VT/AbuseIP for linked domains)
    # ------------------------------------------------------------------

    def check_url_domain_reputation(
        self,
        urls: list[dict] | None = None,
        max_domains: int = 3,
        vt_api_key: str | None = None,
        abuse_api_key: str | None = None,
    ) -> list[dict]:
        """WHOIS, VirusTotal, and AbuseIPDB lookup on domains found in email-body URLs.

        Checks up to *max_domains* unique link domains.

        Returns:
            A list of dicts, each with keys: domain, registrar,
            domain_age_days, is_young, and optionally error, vt_malicious, abuse_flagged.
        """
        if urls is None:
            urls = self.extract_urls()

        # Sender's From domain — exclude it from URL-domain checks.
        from_header = self.msg.get("From") or ""
        at_pos = from_header.rfind("@")
        sender_domain = (
            from_header[at_pos + 1 :].strip().rstrip(">").lower()
            if at_pos != -1
            else None
        )

        seen: set[str] = set()
        domains_to_check: list[str] = []
        for u in urls:
            domain = (u.get("domain") or "").lower()
            if not domain or domain == sender_domain or domain in seen:
                continue
            seen.add(domain)
            domains_to_check.append(domain)
            if len(domains_to_check) >= max_domains:
                break

        results: list[dict] = []
        for domain in domains_to_check:
            rep = self.check_domain_reputation(domain)
            result_dict = {
                "domain": rep.get("domain", domain),
                "registrar": rep.get("registrar"),
                "domain_age_days": rep.get("domain_age_days"),
                "is_young": bool(rep.get("is_young")),
                "error": rep.get("error"),
            }
            if vt_api_key:
                vt = self.check_domain_virustotal(domain, vt_api_key)
                if not vt.get("error"):
                    result_dict["vt_malicious"] = vt.get("is_malicious", False)
            if abuse_api_key:
                try:
                    ip = socket.gethostbyname(domain)
                    abuse = self.check_ip_abuse(ip, abuse_api_key)
                    if not abuse.get("error"):
                        result_dict["abuse_flagged"] = abuse.get("is_flagged", False)
                except OSError:
                    pass
            results.append(result_dict)
        return results

    # ------------------------------------------------------------------
    # Phase 2: DNS record validation
    # ------------------------------------------------------------------

    def validate_dns_records(self, domain: str | None = None) -> dict:
        """Perform live DNS lookups for SPF, DKIM, and DMARC records.

        Compares what the sender domain *publishes* in DNS against the
        authentication results observed in the email headers.

        Args:
            domain: Domain to query. Extracted from ``From`` if omitted.

        Returns:
            A dict with keys:
                - domain    : the domain queried
                - spf       : dict with ``record`` and ``exists`` keys
                - dkim      : dict with ``record`` and ``exists`` keys
                - dmarc     : dict with ``record`` and ``exists`` keys
                - error     : present only on total failure
        """
        if domain is None:
            from_header = self.msg.get("From") or ""
            at_pos = from_header.rfind("@")
            if at_pos == -1:
                return {"domain": None, "error": "No domain in From header"}
            domain = from_header[at_pos + 1:].strip().rstrip(">").lower()

        def _query_txt(name: str) -> list[str]:
            # A resolver per worker keeps concurrent lookups isolated.
            resolver = dns.resolver.Resolver()
            resolver.timeout = _DNS_TIMEOUT
            resolver.lifetime = _DNS_TIMEOUT
            try:
                answers = resolver.resolve(name, "TXT")
                return [rdata.to_text().strip('"') for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    OSError):
                return []

        selectors = ("default", "google", "selector1", "selector2",
                     "s1", "s2", "k1", "dkim", "mail")
        query_names = [domain, f"_dmarc.{domain}"] + [
            f"{selector}._domainkey.{domain}" for selector in selectors
        ]
        records: dict[str, list[str]] = {}
        # All potential DKIM selectors are independent. Query them together so
        # a missing selector costs at most one DNS timeout, not nine.
        with ThreadPoolExecutor(max_workers=len(query_names)) as executor:
            futures = {executor.submit(_query_txt, name): name for name in query_names}
            for future in as_completed(futures):
                records[futures[future]] = future.result()

        spf_record = next((txt for txt in records.get(domain, []) if txt.startswith("v=spf1")), None)
        dmarc_record = next(iter(records.get(f"_dmarc.{domain}", [])), None)
        dkim_record = None
        for selector in selectors:
            selector_records = records.get(f"{selector}._domainkey.{domain}", [])
            dkim_record = next((txt for txt in selector_records if "v=DKIM1" in txt), None)
            if dkim_record:
                break

        return {
            "domain": domain,
            "spf": {"record": spf_record, "exists": spf_record is not None},
            "dkim": {"record": dkim_record, "exists": dkim_record is not None},
            "dmarc": {"record": dmarc_record, "exists": dmarc_record is not None},
        }

    # ------------------------------------------------------------------
    # Phase 2: AbuseIPDB reputation check
    # ------------------------------------------------------------------

    @staticmethod
    def check_ip_abuse(ip: str, api_key: str | None = None) -> dict:
        """Query AbuseIPDB for abuse reports on an IP address.

        Args:
            ip: The IP address to check.
            api_key: AbuseIPDB API key.  If ``None``, the check is skipped
                     gracefully (free tier keys are available at abuseipdb.com).

        Returns:
            A dict with keys:
                - ip                  : the IP queried
                - abuse_score         : confidence-of-abuse percentage (0–100)
                - total_reports       : number of abuse reports
                - country_code        : ISO country code
                - isp                 : ISP name
                - is_flagged          : True if abuse_score >= 25
                - error               : present only on failure
        """
        if api_key is None or not str(api_key).strip():
            return {
                "ip": ip,
                "error": "No AbuseIPDB API key provided — skipped",
            }

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "error": f"Invalid IP address: {ip}"}

        if not addr.is_global:
            return {"ip": ip, "error": "Internal IP — not queried"}

        try:
            resp = requests.get(
                _ABUSEIPDB_API,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=_API_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except requests.exceptions.Timeout:
            return {"ip": ip, "error": "AbuseIPDB request timed out"}
        except requests.exceptions.ConnectionError:
            return {"ip": ip, "error": "Unable to reach AbuseIPDB"}
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status in (401, 403):
                return {
                    "ip": ip,
                    "error": "AbuseIPDB API key is missing, invalid, or expired. Update ABUSEIPDB_API in .env and restart the app.",
                }
            return {"ip": ip, "error": f"AbuseIPDB request failed: {exc}"}
        except requests.exceptions.RequestException as exc:
            return {"ip": ip, "error": f"AbuseIPDB request failed: {exc}"}

        score = data.get("abuseConfidenceScore", 0)
        return {
            "ip": ip,
            "abuse_score": score,
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_flagged": score >= 25,
        }

    # ------------------------------------------------------------------
    # Phase 6: VirusTotal hash lookup
    # ------------------------------------------------------------------

    @staticmethod
    def check_virustotal(file_hash: str, api_key: str | None = None) -> dict:
        """Query VirusTotal for scan results on a file hash.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of a file.
            api_key: VirusTotal API key.  If ``None``, the check is
                     skipped gracefully (free keys available at virustotal.com).

        Returns:
            A dict with keys:
                - hash            : the hash queried
                - detections      : number of engines that flagged the file
                - total_engines   : total number of engines that scanned it
                - detection_rate  : "detections/total" string
                - is_malicious    : True if detections > 0
                - scan_results    : dict of engine_name → verdict (top 10)
                - error           : present only on failure
        """
        if api_key is None:
            return {
                "hash": file_hash,
                "error": "No VirusTotal API key provided — skipped",
            }

        try:
            resp = requests.get(
                _VT_API.format(hash=file_hash),
                headers={"x-apikey": api_key},
                timeout=_API_TIMEOUT,
            )
            if resp.status_code == 404:
                return {
                    "hash": file_hash,
                    "detections": 0,
                    "total_engines": 0,
                    "detection_rate": "Not found in VT database",
                    "is_malicious": False,
                    "scan_results": {},
                }
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
        except requests.exceptions.Timeout:
            return {"hash": file_hash, "error": "VirusTotal request timed out"}
        except requests.exceptions.ConnectionError:
            return {"hash": file_hash, "error": "Unable to reach VirusTotal"}
        except requests.exceptions.RequestException as exc:
            return {"hash": file_hash, "error": f"VirusTotal request failed: {exc}"}

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        detections = malicious + suspicious
        total = sum(stats.values())

        # Extract top detections from engine results.
        results = data.get("last_analysis_results", {})
        flagged = {
            engine: info.get("result", "unknown")
            for engine, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        }
        # Limit to 10 for display.
        top_results = dict(list(flagged.items())[:10])

        return {
            "hash": file_hash,
            "detections": detections,
            "total_engines": total,
            "detection_rate": f"{detections}/{total}",
            "is_malicious": detections > 0,
            "scan_results": top_results,
        }

    # ------------------------------------------------------------------
    # Phase 2: Phishing pattern detection
    # ------------------------------------------------------------------

    def detect_phishing_patterns(self) -> dict:
        """Scan the subject line and body for common phishing language.

        Returns:
            A dict with keys:
                - urgency     : list of matched urgency phrases
                - credential  : list of matched credential-harvesting phrases
                - impersonation: list of matched brand-impersonation phrases
                - total_flags : total number of unique matches
        """
        subject = self.msg.get("Subject") or ""

        # Get plain-text body.
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content()
                    break
                if part.get_content_type() == "text/html":
                    body = BeautifulSoup(
                        part.get_content(), "html.parser"
                    ).get_text(" ")
                    break
        else:
            content = self.msg.get_content()
            if self.msg.get_content_type() == "text/html":
                body = BeautifulSoup(content, "html.parser").get_text(" ")
            else:
                body = content

        combined = f"{subject} {body}"

        urgency = sorted(
            {m.lower() for m in _URGENCY_PATTERNS.findall(combined)}
        )
        credential = sorted(
            {m.lower() for m in _CREDENTIAL_PATTERNS.findall(combined)}
        )
        impersonation = sorted(
            {m.lower() for m in _IMPERSONATION_PATTERNS.findall(combined)}
        )

        return {
            "urgency": urgency,
            "credential": credential,
            "impersonation": impersonation,
            "total_flags": len(urgency) + len(credential) + len(impersonation),
        }

    # ------------------------------------------------------------------
    # Phase 2: Composite risk score (0–100)
    # ------------------------------------------------------------------

    def calculate_risk_score(
        self,
        *,
        auth: dict | None = None,
        urls: list[dict] | None = None,
        attachments: list[dict] | None = None,
        domain_rep: dict | None = None,
        abuse: dict | None = None,
        patterns: dict | None = None,
        spoofing: dict | None = None,
        header_anomalies: dict | None = None,
        url_domain_reps: list[dict] | None = None,
    ) -> dict:
        """Compute a weighted risk score from all available analysis results.

        Each signal contributes a fixed weight (see ``_WEIGHTS``) only when
        the corresponding indicator is positive.  Pre-computed results can
        be passed in to avoid re-running analyses; any that are ``None``
        will be computed on the fly.

        Returns:
            A dict with keys:
                - score       : int 0–100
                - level       : "Critical" / "High" / "Medium" / "Low"
                - breakdown   : dict mapping signal name → (points, reason)
        """
        if auth is None:
            auth = self.check_authentication()
        if urls is None:
            urls = self.extract_urls()
        if attachments is None:
            attachments = self.extract_attachments()
        if patterns is None:
            patterns = self.detect_phishing_patterns()
        if spoofing is None:
            spoofing = self.detect_spoofing()
        if header_anomalies is None:
            header_anomalies = self.detect_header_anomalies()

        score = 0
        breakdown: dict[str, tuple[int, str]] = {}

        # 0. Identity spoofing (display-name / Reply-To / Return-Path)
        # Multiple findings contribute with diminishing returns: the first
        # (highest-severity) finding receives its full weight, each additional
        # finding receives a smaller fixed bonus.  The total is capped at
        # 1.5× the base weight so this category alone can't dominate the
        # score even with many piled-up findings.
        if spoofing.get("is_spoofed"):
            _sev_order = {"high": 0, "medium": 1, "low": 2}
            sorted_findings = sorted(
                spoofing.get("findings", []),
                key=lambda f: _sev_order.get(f.get("severity", "low"), 2),
            )
            spoofing_cap = _WEIGHTS["spoofing"] + _WEIGHTS["spoofing"] // 2
            spoof_pts = 0
            for i, finding in enumerate(sorted_findings):
                sev = finding.get("severity", "low")
                if i == 0:
                    # First (highest-severity) finding: full weight
                    if sev == "high":
                        pts = _WEIGHTS["spoofing"]
                    elif sev == "medium":
                        pts = _WEIGHTS["spoofing"] // 2
                    else:
                        pts = _WEIGHTS["spoofing"] // 4
                else:
                    # Additional findings: smaller fixed bonus
                    if sev in ("high", "medium"):
                        pts = _WEIGHTS["spoofing"] // 4
                    else:
                        pts = _WEIGHTS["spoofing"] // 8
                spoof_pts = min(spoof_pts + pts, spoofing_cap)
            score += spoof_pts
            breakdown["spoofing"] = (
                spoof_pts,
                "; ".join(f["message"] for f in sorted_findings),
            )

        # 1. Authentication failures
        if auth.get("is_suspicious"):
            spf_dkim_dmarc_failures = [p for p in ("spf", "dkim", "dmarc")
                                       if auth.get(p) in ("fail", "softfail")]
            if spf_dkim_dmarc_failures:
                pts = _WEIGHTS["auth_fail"]
                score += pts
                breakdown["auth_fail"] = (pts, f"{', '.join(f.upper() for f in spf_dkim_dmarc_failures)} failed")

        # 1b. Microsoft composite authentication (compauth)
        if auth.get("compauth") == "fail":
            pts = _WEIGHTS["compauth_fail"]
            reason_code = auth.get("compauth_reason", "unknown")
            score += pts
            breakdown["compauth_fail"] = (
                pts,
                f"Microsoft composite authentication failed (reason={reason_code})"
                f" — sending domain doesn't match displayed From address.",
            )

        # 2. URL mismatches
        mismatches = [u for u in urls if u.get("mismatch")]
        if mismatches:
            pts = _WEIGHTS["url_mismatch"]
            score += pts
            breakdown["url_mismatch"] = (pts, f"{len(mismatches)} link(s) with domain mismatch")

        # 3. Risky attachments
        risky = [a for a in attachments if a.get("risky")]
        if risky:
            pts = _WEIGHTS["risky_attachment"]
            score += pts
            names = ", ".join(a["filename"] for a in risky)
            breakdown["risky_attachment"] = (pts, f"Dangerous files: {names}")

        # 4. Young domain
        if domain_rep and not domain_rep.get("error") and domain_rep.get("is_young"):
            pts = _WEIGHTS["young_domain"]
            score += pts
            age = domain_rep.get("domain_age_days", "?")
            breakdown["young_domain"] = (pts, f"Domain only {age} days old")

        # 5. AbuseIPDB
        if abuse and not abuse.get("error") and abuse.get("is_flagged"):
            pts = _WEIGHTS["abuse_ip"]
            score += pts
            breakdown["abuse_ip"] = (
                pts,
                f"Abuse score {abuse['abuse_score']}%, "
                f"{abuse['total_reports']} reports",
            )

        # 6. Urgency language
        if patterns.get("urgency"):
            pts = _WEIGHTS["urgency_lang"]
            score += pts
            breakdown["urgency_lang"] = (
                pts,
                f"Matched: {', '.join(patterns['urgency'][:5])}",
            )

        # 7. Credential harvesting language
        if patterns.get("credential"):
            pts = _WEIGHTS["credential_lang"]
            score += pts
            breakdown["credential_lang"] = (
                pts,
                f"Matched: {', '.join(patterns['credential'][:5])}",
            )

        # 8. Brand impersonation
        if patterns.get("impersonation"):
            pts = _WEIGHTS["impersonation"]
            score += pts
            breakdown["impersonation"] = (
                pts,
                f"Matched: {', '.join(patterns['impersonation'][:5])}",
            )

        # 9. Header anomaly — DKIM signing domain mismatch (not in spoofing)
        dkim_anomaly = any(
            "DKIM signing domain" in a
            for a in header_anomalies.get("anomalies", [])
        )
        spoofing_covers_dkim = any(
            "DKIM" in f.get("message", "")
            for f in (spoofing or {}).get("findings", [])
        )
        if dkim_anomaly and not spoofing_covers_dkim:
            pts = _WEIGHTS["header_anomaly"]
            score += pts
            breakdown["header_anomaly"] = (
                pts,
                "DKIM signing domain differs from From domain.",
            )

        # 10. Young URL domain — a link in the body points to a recently
        #     registered domain.
        if url_domain_reps:
            young_domains = [
                entry["domain"]
                for entry in url_domain_reps
                if entry.get("is_young")
            ]
            if young_domains:
                pts = _WEIGHTS["young_url_domain"]
                score += pts
                breakdown["young_url_domain"] = (
                    pts,
                    f"Linked domain '{young_domains[0]}' registered recently.",
                )

            vt_bad = [entry["domain"] for entry in url_domain_reps if entry.get("vt_malicious")]
            if vt_bad:
                pts = _WEIGHTS["vt_url_malicious"]
                score += pts
                breakdown["vt_url_malicious"] = (
                    pts,
                    f"Linked domain '{vt_bad[0]}' flagged by VirusTotal.",
                )

            abuse_bad = [entry["domain"] for entry in url_domain_reps if entry.get("abuse_flagged")]
            if abuse_bad:
                pts = _WEIGHTS["abuseip_url"]
                score += pts
                breakdown["abuseip_url"] = (
                    pts,
                    f"IP for linked domain '{abuse_bad[0]}' flagged by AbuseIPDB.",
                )

        # 11. Homograph domain
        homographs = [u.get("domain") for u in (urls or []) if u.get("is_homograph")]
        if homographs:
            pts = _WEIGHTS["homograph_domain"]
            score += pts
            breakdown["homograph_domain"] = (
                pts,
                f"Linked domain '{homographs[0]}' uses punycode or mimics a known brand.",
            )

        # Determine threat level.
        if score >= 75:
            level = "Critical"
        elif score >= 50:
            level = "High"
        elif score >= 25:
            level = "Medium"
        else:
            level = "Low"

        return {"score": score, "level": level, "breakdown": breakdown}

    # ------------------------------------------------------------------
    # Phase 1: Deeper header analysis
    # ------------------------------------------------------------------

    def _extract_domain(self, header_value: str) -> str | None:
        """Extract the bare domain from a header like 'Name <user@domain>'."""
        if not header_value:
            return None
        at = header_value.rfind("@")
        if at == -1:
            return None
        return header_value[at + 1:].strip().rstrip(">").lower()

    def detect_header_anomalies(self) -> dict:
        """Flag mismatches between identity-related headers.

        Checks:
            1. From vs. Reply-To domain mismatch.
            2. From vs. Return-Path domain mismatch.
            3. From vs. DKIM ``d=`` domain mismatch (extracted from
               ``Authentication-Results`` header).
            4. Presence of Reply-To pointing to a different domain
               (common phishing redirect).

        Returns:
            A dict with:
                - domains    : dict of header → extracted domain
                - anomalies  : list of human-readable anomaly strings
                - is_anomalous: True if any anomalies were found
        """
        from_hdr = self.msg.get("From") or ""
        reply_to = self.msg.get("Reply-To") or ""
        return_path = self.msg.get("Return-Path") or ""
        auth_results = self.msg.get("Authentication-Results") or ""

        from_domain = self._extract_domain(from_hdr)
        reply_domain = self._extract_domain(reply_to)
        return_domain = self._extract_domain(return_path)

        # DKIM d= domain from Authentication-Results.
        dkim_d_match = re.search(
            r"dkim=\w+[^;]*?header\.(?:d|i)=@?([\w.\-]+)", auth_results, re.IGNORECASE
        )
        dkim_domain = dkim_d_match.group(1).lower() if dkim_d_match else None
        if dkim_domain in ("none", "unknown", ""):
            dkim_domain = None

        domains = {
            "From": from_domain,
            "Reply-To": reply_domain,
            "Return-Path": return_domain,
            "DKIM d=": dkim_domain,
        }

        anomalies: list[str] = []

        if reply_domain and from_domain and reply_domain != from_domain:
            anomalies.append(
                f"Reply-To ({reply_domain}) differs from From ({from_domain})"
            )

        if return_domain and from_domain and return_domain != from_domain:
            anomalies.append(
                f"Return-Path ({return_domain}) differs from From ({from_domain})"
            )

        if dkim_domain and from_domain and dkim_domain != from_domain:
            anomalies.append(
                f"DKIM signing domain ({dkim_domain}) differs from From ({from_domain})"
            )

        return {
            "domains": domains,
            "anomalies": anomalies,
            "is_anomalous": len(anomalies) > 0,
        }

    @staticmethod
    def _normalize_name_tokens(text: str) -> set[str]:
        """Tokenize a personal-name string for comparison.

        Strips diacritics ('José' → 'jose'), lowercases, splits on
        non-letters, and drops honorifics / particles listed in
        ``_NAME_NOISE_TOKENS``.
        """
        if not text:
            return set()
        decomposed = unicodedata.normalize("NFKD", text)
        ascii_text = "".join(
            ch for ch in decomposed if not unicodedata.combining(ch)
        )
        tokens = {t.lower() for t in _NAME_TOKEN_RE.findall(ascii_text)}
        return tokens - _NAME_NOISE_TOKENS

    @staticmethod
    def _local_part_matches_name(local_part: str, name_tokens: set[str]) -> bool:
        """Heuristic: does the email local-part plausibly belong to ``name_tokens``?

        A token "matches" when either:
            * it appears as a substring of the letters-only local-part
              (covers ``john.smith``, ``jsmith``, ``john_smith2003``,
              ``smithjohn``); OR
            * its first letter appears alongside a full match of another
              token from the same name (covers ``j.smith``, ``jsmith``,
              ``smith.j``).
        """
        if not name_tokens or not local_part:
            return False
        cleaned = re.sub(r"[^a-z]", "", local_part.lower())
        if not cleaned:
            return False

        full_matches = {
            t for t in name_tokens
            if len(t) >= _NAME_TOKEN_MIN_MATCH_LEN and t in cleaned
        }
        if full_matches:
            return True

        # Initial + sibling-token match (e.g. "j" alongside "smith").
        for tok in name_tokens:
            initial = tok[0]
            if initial not in cleaned:
                continue
            siblings = name_tokens - {tok}
            if any(
                len(s) >= _NAME_TOKEN_MIN_MATCH_LEN and s in cleaned
                for s in siblings
            ):
                return True
        return False

    def detect_spoofing(self) -> dict:
        """Detect identity-spoofing tells in the From / Reply-To / Return-Path.

        Four independent checks:

        1. **Display-name brand impersonation** — the From display name
           contains a brand keyword (e.g. "Microsoft Support") but the
           email address is not on that brand's known sender domains.
        2. **Free-mail with corporate display name** — sender uses a
           public webmail provider (gmail/yahoo/outlook/...) but presents
           a corporate role display name (Support, Admin, Security, etc.).
        3. **Display-name vs. local-part mismatch** — a personal name in
           the display field that has no token in common with the email
           local-part (e.g. "Maryam Inam" sent from
           ``zainabshehzad2003@gmail.com``). Classic friendly-from spoof.
        4. **Reply-To / Return-Path divergence** — surfaces these as
           explicit verdicts (low / medium / high severity) rather than
           just listing the mismatch.

        Returns:
            A dict with:
                - from_display    : str | None
                - from_address    : str | None
                - from_domain     : str | None
                - reply_to        : str | None
                - return_path     : str | None
                - findings        : list[{type, severity, message}]
                - severity        : "high" | "medium" | "low" | "none"
                - is_spoofed      : bool — True for medium+ findings
        """
        from_hdr = self.msg.get("From") or ""
        reply_to_hdr = self.msg.get("Reply-To") or ""
        return_path_hdr = self.msg.get("Return-Path") or ""

        display_name, addr = email.utils.parseaddr(from_hdr)
        from_addr = addr.lower() if addr else None
        from_domain = from_addr.split("@", 1)[1] if from_addr and "@" in from_addr else None
        display_name = (display_name or "").strip()

        _, reply_addr = email.utils.parseaddr(reply_to_hdr)
        reply_addr = reply_addr.lower() if reply_addr else None
        reply_domain = (
            reply_addr.split("@", 1)[1] if reply_addr and "@" in reply_addr else None
        )

        # Return-Path may be "<>" or "<addr@domain>"
        rp_clean = return_path_hdr.strip().strip("<>").lower()
        return_domain = rp_clean.split("@", 1)[1] if rp_clean and "@" in rp_clean else None

        findings: list[dict] = []

        def _suffix_match(domain: str, allowed: set[str]) -> bool:
            return any(domain == d or domain.endswith("." + d) for d in allowed)

        # 1. Brand impersonation in display name.
        if display_name and from_domain:
            dn_lower = display_name.lower()
            for brand, legit_domains in _BRAND_DOMAINS.items():
                if brand in dn_lower:
                    if not _suffix_match(from_domain, legit_domains):
                        findings.append({
                            "type": "brand_impersonation",
                            "severity": "high",
                            "message": (
                                f"Display name claims \"{brand.title()}\" but "
                                f"From domain is {from_domain} — not a known "
                                f"{brand.title()} sender."
                            ),
                        })
                        break  # one brand finding is enough

        # 2. Free-mail provider with corporate-role display name.
        if from_domain and from_domain in _FREE_MAIL_PROVIDERS and display_name:
            if _CORPORATE_DISPLAY_TERMS.search(display_name):
                findings.append({
                    "type": "freemail_corporate_persona",
                    "severity": "high",
                    "message": (
                        f"Corporate-style display name \"{display_name}\" "
                        f"sent from public webmail ({from_domain})."
                    ),
                })

        # 3. Display-name vs. local-part mismatch (friendly-from spoof).
        # Skipped when branch 1 or 2 already classified this sender, since
        # those branches describe a stronger, more specific impersonation.
        already_classified = any(
            f["type"] in ("brand_impersonation", "freemail_corporate_persona")
            for f in findings
        )
        if (
            not already_classified
            and display_name
            and from_addr
            and "@" in from_addr
            and not _CORPORATE_DISPLAY_TERMS.search(display_name)
        ):
            name_tokens = self._normalize_name_tokens(display_name)
            local_part = from_addr.split("@", 1)[0]
            if name_tokens and not self._local_part_matches_name(
                local_part, name_tokens
            ):
                findings.append({
                    "type": "display_name_mismatch",
                    "severity": "medium",
                    "message": (
                        f"Display name \"{display_name}\" does not match "
                        f"the email local-part \"{local_part}\" — "
                        f"possible friendly-from spoof."
                    ),
                })

        # 4. Reply-To divergence — explicit verdict.
        if reply_domain and from_domain and reply_domain != from_domain:
            same_org = (
                reply_domain.endswith("." + from_domain)
                or from_domain.endswith("." + reply_domain)
            )
            if same_org:
                sev = "low"
                msg = (
                    f"Reply-To ({reply_domain}) is a subdomain of From "
                    f"({from_domain}) — likely benign."
                )
            elif reply_domain in _FREE_MAIL_PROVIDERS \
                    and from_domain not in _FREE_MAIL_PROVIDERS:
                sev = "high"
                msg = (
                    f"Reply-To redirects replies to free webmail "
                    f"({reply_domain}) while From claims {from_domain}."
                )
            else:
                sev = "medium"
                msg = (
                    f"Reply-To ({reply_domain}) differs from From "
                    f"({from_domain}) — replies will not reach the apparent sender."
                )
            findings.append({
                "type": "reply_to_divergence",
                "severity": sev,
                "message": msg,
            })

        # 5. Return-Path divergence — explicit verdict.
        if return_domain and from_domain and return_domain != from_domain:
            # Same org / parent domain — common for ESPs (e.g. mailgun bounces).
            same_org = (
                return_domain.endswith("." + from_domain)
                or from_domain.endswith("." + return_domain)
            )
            if same_org:
                sev = "low"
                msg = (
                    f"Return-Path ({return_domain}) is related to From "
                    f"({from_domain}) — typical ESP bounce setup."
                )
            else:
                sev = "medium"
                msg = (
                    f"Return-Path ({return_domain}) differs from From "
                    f"({from_domain}) — bounces go elsewhere; possible spoof."
                )
            findings.append({
                "type": "return_path_divergence",
                "severity": sev,
                "message": msg,
            })

        # Roll-up severity.
        sev_rank = {"high": 3, "medium": 2, "low": 1, "none": 0}
        top = "none"
        for f in findings:
            if sev_rank[f["severity"]] > sev_rank[top]:
                top = f["severity"]

        return {
            "from_display": display_name or None,
            "from_address": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_addr,
            "return_path": rp_clean or None,
            "findings": findings,
            "severity": top,
            "is_spoofed": top in ("high", "medium"),
        }

    def analyze_timestamps(self) -> dict:
        """Inspect Received-header timestamps for forensic anomalies.

        Checks:
            1. Time-travel: a hop whose timestamp is *earlier* than the
               previous hop (email arrived before it was sent).
            2. Excessive delay: gaps larger than ``_MAX_HOP_DELTA_SECONDS``
               between consecutive hops.
            3. Future-dated: the ``Date`` header is in the future.

        Returns:
            A dict with:
                - hops           : list of dicts (hop, timestamp_raw, parsed_dt)
                - anomalies      : list of human-readable anomaly strings
                - is_anomalous   : True if any anomalies were found
        """
        received_headers: list[str] = self.msg.get_all("Received") or []
        # Chronological order (oldest first).
        received_headers = list(reversed(received_headers))

        parsed_hops: list[dict] = []
        anomalies: list[str] = []

        for idx, raw in enumerate(received_headers, start=1):
            header = " ".join(raw.split())
            ts_match = _TIMESTAMP_RE.search(header)
            ts_raw = ts_match.group(1).strip() if ts_match else None
            parsed_dt = None
            if ts_raw:
                parsed_tuple = email.utils.parsedate_to_datetime(ts_raw)
                if parsed_tuple:
                    parsed_dt = parsed_tuple.astimezone(timezone.utc)
            parsed_hops.append({
                "hop": idx,
                "timestamp_raw": ts_raw,
                "parsed_dt": parsed_dt,
            })

        # Compare consecutive hops.
        for i in range(1, len(parsed_hops)):
            prev_dt = parsed_hops[i - 1].get("parsed_dt")
            curr_dt = parsed_hops[i].get("parsed_dt")
            if prev_dt is None or curr_dt is None:
                continue

            delta = (curr_dt - prev_dt).total_seconds()

            if delta < 0:
                anomalies.append(
                    f"Hop {parsed_hops[i]['hop']}: time-travel detected — "
                    f"arrived {abs(delta):.0f}s before previous hop"
                )
            elif delta > _MAX_HOP_DELTA_SECONDS:
                anomalies.append(
                    f"Hop {parsed_hops[i]['hop']}: excessive delay — "
                    f"{delta / 3600:.1f} hours between hops"
                )

        # Check if the Date header is in the future.
        date_hdr = self.msg.get("Date")
        if date_hdr:
            try:
                msg_dt = email.utils.parsedate_to_datetime(date_hdr)
                msg_dt = msg_dt.astimezone(timezone.utc)
                now = datetime.now(timezone.utc)
                if msg_dt > now:
                    diff = (msg_dt - now).total_seconds()
                    anomalies.append(
                        f"Date header is {diff / 3600:.1f} hours in the future"
                    )
            except (TypeError, ValueError):
                anomalies.append("Date header could not be parsed")

        return {
            "hops": parsed_hops,
            "anomalies": anomalies,
            "is_anomalous": len(anomalies) > 0,
        }

    def extract_x_headers(self) -> dict:
        """Extract forensically interesting X-headers from the message.

        Returns:
            A dict mapping header names to their values (or lists of
            values when a header appears more than once).  Only headers
            that are present are included.
        """
        result: dict[str, str | list[str]] = {}

        for hdr in _FORENSIC_X_HEADERS:
            values = self.msg.get_all(hdr)
            if not values:
                continue
            # Collapse folded whitespace in each value.
            values = [" ".join(v.split()) for v in values]
            result[hdr] = values[0] if len(values) == 1 else values

        return result

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------

    def extract_iocs(
        self,
        *,
        routing: list[dict] | None = None,
        urls: list[dict] | None = None,
        attachments: list[dict] | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Aggregate all Indicators of Compromise from analysis results.

        Returns a dict with keys: ips, domains, urls, emails, hashes.
        Pure aggregation — no network calls.
        """
        ioc_ips: set[str] = set()
        ioc_domains: set[str] = set()
        ioc_urls: set[str] = set()
        ioc_emails: set[str] = set()
        ioc_hashes: list[dict] = []

        # IPs from routing hops
        if routing:
            for hop in routing:
                ip = hop.get("ip")
                if ip:
                    try:
                        if ipaddress.ip_address(ip).is_global:
                            ioc_ips.add(ip)
                    except ValueError:
                        pass

        # X-Originating-IP
        x_orig = self.msg.get("X-Originating-IP")
        if x_orig:
            cleaned = x_orig.strip().strip("[]")
            try:
                if ipaddress.ip_address(cleaned).is_global:
                    ioc_ips.add(cleaned)
            except ValueError:
                pass

        # Originating IP from routing
        if self.originating_ip:
            ioc_ips.add(self.originating_ip)

        # URLs and domains from URL extraction
        if urls:
            for u in urls:
                if u.get("url"):
                    ioc_urls.add(u["url"])
                if u.get("domain"):
                    ioc_domains.add(u["domain"])

        # Email addresses and domains from headers
        for hdr_name in ("From", "To", "Reply-To", "Return-Path"):
            raw = self.msg.get(hdr_name)
            if raw:
                _, addr = email.utils.parseaddr(raw)
                if addr and "@" in addr:
                    ioc_emails.add(addr)
                    domain = addr.split("@", 1)[1].lower()
                    ioc_domains.add(domain)

        # File hashes from attachments
        if attachments:
            for att in attachments:
                ioc_hashes.append({
                    "filename": att["filename"],
                    "md5": att["md5"],
                    "sha256": att["sha256"],
                })

        return {
            "ips": sorted(ioc_ips),
            "domains": sorted(ioc_domains),
            "urls": sorted(ioc_urls),
            "emails": sorted(ioc_emails),
            "hashes": ioc_hashes,
        }

    # ------------------------------------------------------------------
    # Phase 4: HTML report generation
    # ------------------------------------------------------------------

    @staticmethod
    def _esc(text: str | None) -> str:
        """HTML-escape a string, returning '—' for None/empty."""
        if not text:
            return "&mdash;"
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def generate_html_report(
        self,
        *,
        metadata: dict | None = None,
        routing: list[dict] | None = None,
        auth: dict | None = None,
        header_analysis: dict | None = None,
        geo: list[tuple[str, dict]] | None = None,
        urls: list[dict] | None = None,
        attachments: list[dict] | None = None,
        domain_rep: dict | None = None,
        threat_intel: dict | None = None,
        url_domain_reps: list[dict] | None = None,
    ) -> str:
        """Generate a self-contained HTML forensic report.

        Pre-computed analysis results can be passed in to avoid
        re-running analyses.  Any that are ``None`` will be computed
        on the fly (except geo / domain_rep / threat_intel which
        require network calls and are simply omitted when absent).

        Returns:
            A complete HTML document as a string.
        """
        esc = self._esc

        if metadata is None:
            metadata = self.extract_basic_metadata()
        if routing is None:
            routing = self.extract_routing_path()
        if auth is None:
            auth = self.check_authentication()
        if header_analysis is None:
            header_analysis = {
                "anomalies": self.detect_header_anomalies(),
                "timestamps": self.analyze_timestamps(),
                "x_headers": self.extract_x_headers(),
                "spoofing": self.detect_spoofing(),
            }
        if urls is None:
            urls = self.extract_urls()
        if attachments is None:
            attachments = self.extract_attachments()

        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # ── Risk score banner ───────────────────────────────────
        risk_html = ""
        if threat_intel and "risk" in threat_intel:
            risk = threat_intel["risk"]
            score = risk["score"]
            level = risk["level"]
            if score >= 75:
                badge_color = "#e74c3c"
            elif score >= 50:
                badge_color = "#f39c12"
            elif score >= 25:
                badge_color = "#3498db"
            else:
                badge_color = "#2ecc71"
            risk_html = f"""
            <div class="risk-banner" style="background:{badge_color}">
                <span class="risk-score">{score}/100</span>
                <span class="risk-level">{esc(level)}</span>
            </div>"""

        # ── Metadata ────────────────────────────────────────────
        meta_rows = "\n".join(
            f"<tr><td class='lbl'>{esc(k)}</td><td>{esc(str(v))}</td></tr>"
            for k, v in metadata.items()
        )

        # ── Authentication ──────────────────────────────────────
        auth_rows = ""
        for proto in ("spf", "dkim", "dmarc"):
            status = auth.get(proto)
            display = (status or "NOT PRESENT").upper()
            cls = "pass" if status == "pass" else ("fail" if status in ("fail", "softfail") else "neutral")
            auth_rows += f"<tr><td class='lbl'>{proto.upper()}</td><td class='{cls}'>{esc(display)}</td></tr>\n"
        # Microsoft compauth row (only when present in headers).
        compauth_val = auth.get("compauth")
        if compauth_val is not None:
            ca_display = compauth_val.upper()
            ca_cls = "pass" if compauth_val == "pass" else ("fail" if compauth_val == "fail" else "neutral")
            reason_suffix = f" (reason={auth['compauth_reason']})" if auth.get("compauth_reason") else ""
            auth_rows += f"<tr><td class='lbl'>COMPAUTH</td><td class='{ca_cls}'>{esc(ca_display + reason_suffix)}</td></tr>\n"
        verdict_cls = "fail" if auth.get("is_suspicious") else "pass"
        verdict_text = "SUSPICIOUS — one or more checks failed" if auth.get("is_suspicious") else "No failures detected"
        auth_rows += f"<tr><td class='lbl'>Verdict</td><td class='{verdict_cls}'><strong>{esc(verdict_text)}</strong></td></tr>"

        # ── Header analysis ─────────────────────────────────────
        header_html = ""
        if header_analysis:
            anomalies = header_analysis.get("anomalies", {})
            timestamps = header_analysis.get("timestamps", {})
            x_headers = header_analysis.get("x_headers", {})
            spoofing_info = header_analysis.get("spoofing", {})

            # Domains
            domain_rows = ""
            for hdr_name, domain in anomalies.get("domains", {}).items():
                domain_rows += f"<tr><td class='lbl'>{esc(hdr_name)}</td><td>{esc(domain)}</td></tr>\n"

            anomaly_rows = ""
            if anomalies.get("is_anomalous"):
                for line in anomalies.get("anomalies", []):
                    anomaly_rows += f"<tr><td class='lbl'>Warning</td><td class='fail'><strong>{esc(line)}</strong></td></tr>\n"
            else:
                anomaly_rows = "<tr><td class='lbl'>Status</td><td class='pass'><strong>All identity headers are consistent</strong></td></tr>"
            
            # Spoofing / identity findings
            spoof_rows = ""
            findings = spoofing_info.get("findings", [])
            if findings:
                for f in findings:
                    sev = f.get("severity", "low")
                    cls = "fail" if sev in ("high", "medium") else "neutral"
                    spoof_rows += (
                        f"<tr><td class='lbl'>{esc(sev.upper())}</td>"
                        f"<td class='{cls}'><strong>{esc(f.get('message'))}</strong></td></tr>\n"
                    )
            else:
                spoof_rows = "<tr><td class='pass' colspan='2'><strong>No spoofing indicators detected</strong></td></tr>"

            spoof_html = f"""
            <h3>Identity Spoofing Findings</h3>
            <table>
              <tr><td class='lbl'>Display Name</td><td>{esc(spoofing_info.get('from_display'))}</td></tr>
              <tr><td class='lbl'>From Address</td><td>{esc(spoofing_info.get('from_address'))}</td></tr>
              <tr><td class='lbl'>Overall Severity</td><td class='{"fail" if spoofing_info.get("is_spoofed") else "pass"}'><strong>{esc(spoofing_info.get('severity', 'none').upper())}</strong></td></tr>
              {spoof_rows}
            </table>"""

            # Timestamps
            ts_rows = ""
            for hop in timestamps.get("hops", []):
                dt = hop.get("parsed_dt")
                dt_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "unparseable"
                ts_rows += f"<tr><td class='lbl'>Hop {hop['hop']}</td><td>{esc(dt_str)}</td></tr>\n"

            ts_anomaly_rows = ""
            if timestamps.get("is_anomalous"):
                for line in timestamps.get("anomalies", []):
                    ts_anomaly_rows += f"<tr><td class='lbl'>Warning</td><td class='fail'><strong>{esc(line)}</strong></td></tr>\n"
            else:
                ts_anomaly_rows = "<tr><td class='lbl'>Status</td><td class='pass'><strong>No timing anomalies detected</strong></td></tr>"

            # X-Headers
            xh_rows = ""
            if x_headers:
                for hdr_name, value in x_headers.items():
                    if isinstance(value, list):
                        for v in value:
                            xh_rows += f"<tr><td class='lbl'>{esc(hdr_name)}</td><td>{esc(v)}</td></tr>\n"
                    else:
                        xh_rows += f"<tr><td class='lbl'>{esc(hdr_name)}</td><td>{esc(value)}</td></tr>\n"
            else:
                xh_rows = "<tr><td colspan='2' class='neutral'>No forensic X-Headers present</td></tr>"

            header_html = f"""
            <h2>Header Analysis</h2>
            <h3>Identity Verification</h3>
            <table>{domain_rows}{anomaly_rows}</table>
            {spoof_html}
            <h3>Timestamp Analysis</h3>
            <table>{ts_rows}{ts_anomaly_rows}</table>
            <h3>Forensic X-Headers</h3>
            <table>{xh_rows}</table>"""

        # ── Routing path ────────────────────────────────────────
        route_rows = ""
        if routing:
            for hop in routing:
                route_rows += (
                    f"<tr><td>{hop['hop']}</td><td>{esc(hop['from'])}</td>"
                    f"<td>{esc(hop['by'])}</td><td>{esc(hop['ip'])}</td>"
                    f"<td>{esc(hop['timestamp'])}</td></tr>\n"
                )
        else:
            route_rows = "<tr><td colspan='5'>No Received headers found.</td></tr>"

        # ── Geolocation ─────────────────────────────────────────
        geo_html = ""
        if geo:
            geo_rows = ""
            for ip, info in geo:
                if "error" in info:
                    geo_rows += f"<tr><td class='lbl'>{esc(ip)}</td><td class='fail'>{esc(info['error'])}</td></tr>\n"
                elif info.get("note"):
                    geo_rows += f"<tr><td class='lbl'>{esc(ip)}</td><td class='neutral'>{esc(info['note'])}</td></tr>\n"
                else:
                    geo_rows += (
                        f"<tr><td class='lbl'>{esc(ip)}</td>"
                        f"<td>{esc(info.get('country'))} / {esc(info.get('city'))} "
                        f"— {esc(info.get('isp'))} ({esc(info.get('asn'))})</td></tr>\n"
                    )
            geo_html = f"<h2>IP Geolocation</h2><table>{geo_rows}</table>"

        # ── URLs ────────────────────────────────────────────────
        url_rows = ""
        if urls:
            for i, u in enumerate(urls, 1):
                mismatch = " class='fail'" if u["mismatch"] else ""
                mm_badge = " <strong>[MISMATCH]</strong>" if u["mismatch"] else ""
                url_rows += (
                    f"<tr{mismatch}><td>{i}</td><td>{esc(u['url'])}</td>"
                    f"<td>{esc(u['domain'])}</td>"
                    f"<td>{esc(u.get('display_text'))}{mm_badge}</td></tr>\n"
                )
        else:
            url_rows = "<tr><td colspan='4'>No URLs found in message body.</td></tr>"

        # ── Domain reputation ───────────────────────────────────
        domain_html = ""
        if domain_rep:
            if "error" in domain_rep:
                domain_html = f"<h3>Sender Domain Reputation</h3><p class='fail'>{esc(domain_rep['error'])}</p>"
            else:
                young_cls = "fail" if domain_rep.get("is_young") else "pass"
                age = domain_rep.get("domain_age_days")
                age_str = f"{age} days" if age is not None else "&mdash;"
                domain_html = f"""
                <h3>Sender Domain Reputation</h3>
                <table>
                    <tr><td class='lbl'>Domain</td><td>{esc(domain_rep.get('domain'))}</td></tr>
                    <tr><td class='lbl'>Registrar</td><td>{esc(domain_rep.get('registrar'))}</td></tr>
                    <tr><td class='lbl'>Created</td><td>{esc(domain_rep.get('creation_date'))}</td></tr>
                    <tr><td class='lbl'>Domain Age</td><td class='{young_cls}'><strong>{age_str}</strong></td></tr>
                </table>"""

        # ── URL domain reputation (linked domains) ─────────────
        url_domain_html = ""
        if url_domain_reps:
            udr_rows = ""
            for entry in url_domain_reps:
                if entry.get("error"):
                    udr_rows += (
                        f"<tr><td>{esc(entry.get('domain', ''))}</td>"
                        f"<td colspan='3' class='neutral'>{esc(entry['error'])}</td></tr>\n"
                    )
                else:
                    age = entry.get("domain_age_days")
                    age_str = f"{age} days" if age is not None else "&mdash;"
                    young_cls = "fail" if entry.get("is_young") else "pass"
                    udr_rows += (
                        f"<tr><td>{esc(entry.get('domain', ''))}</td>"
                        f"<td>{esc(entry.get('registrar'))}</td>"
                        f"<td class='{young_cls}'><strong>{age_str}</strong></td>"
                        f"<td class='{young_cls}'>{'YES' if entry.get('is_young') else 'No'}</td></tr>\n"
                    )
            url_domain_html = f"""
            <h3>Linked Domain Reputation</h3>
            <table>
                <tr><th>Domain</th><th>Registrar</th><th>Age</th><th>Young?</th></tr>
                {udr_rows}
            </table>"""

        # ── Attachments ─────────────────────────────────────────
        attach_rows = ""
        if attachments:
            for i, att in enumerate(attachments, 1):
                risky_cls = " class='fail'" if att["risky"] else ""
                badge = " <strong>[RISKY]</strong>" if att["risky"] else ""
                attach_rows += (
                    f"<tr{risky_cls}><td>{i}</td><td>{esc(att['filename'])}{badge}</td>"
                    f"<td>{esc(att['mime_type'])}</td><td>{att['size']:,}</td>"
                    f"<td style='font-family:monospace;font-size:11px'>{esc(att['md5'])}</td>"
                    f"<td style='font-family:monospace;font-size:11px'>{esc(att['sha256'])}</td></tr>\n"
                )
        else:
            attach_rows = "<tr><td colspan='6'>No attachments found.</td></tr>"

        # ── Threat intel ────────────────────────────────────────
        threat_html = ""
        if threat_intel:
            risk = threat_intel.get("risk", {})
            dns_rec = threat_intel.get("dns", {})
            patterns = threat_intel.get("patterns", {})
            abuse = threat_intel.get("abuse", {})

            # Breakdown
            breakdown_rows = ""
            for _, (pts, reason) in risk.get("breakdown", {}).items():
                breakdown_rows += f"<tr><td class='fail'><strong>+{pts} pts</strong></td><td class='fail'>{esc(reason)}</td></tr>\n"

            # DNS
            dns_rows = ""
            if dns_rec.get("error"):
                dns_rows = f"<tr><td class='lbl'>Error</td><td class='fail'>{esc(dns_rec['error'])}</td></tr>"
            else:
                dns_rows += f"<tr><td class='lbl'>Domain</td><td>{esc(dns_rec.get('domain'))}</td></tr>\n"
                for proto in ("spf", "dkim", "dmarc"):
                    rec = dns_rec.get(proto, {})
                    exists = rec.get("exists", False)
                    cls = "pass" if exists else "fail"
                    status_text = "PUBLISHED" if exists else "NOT FOUND"
                    dns_rows += f"<tr><td class='lbl'>{proto.upper()}</td><td class='{cls}'><strong>{esc(status_text)}</strong></td></tr>\n"
                    if rec.get("record"):
                        record_text = rec["record"]
                        if len(record_text) > 120:
                            record_text = record_text[:117] + "..."
                        dns_rows += f"<tr><td></td><td class='neutral' style='font-size:11px'>{esc(record_text)}</td></tr>\n"

            # Patterns
            pattern_rows = ""
            total = patterns.get("total_flags", 0)
            if total == 0:
                pattern_rows = "<tr><td class='lbl'>Result</td><td class='pass'><strong>No suspicious language detected</strong></td></tr>"
            else:
                pattern_rows += f"<tr><td class='lbl'>Flags Found</td><td class='fail'><strong>{total}</strong></td></tr>\n"
                for category, label in [("urgency", "Urgency"), ("credential", "Credential Harvesting"), ("impersonation", "Brand Impersonation")]:
                    matches = patterns.get(category, [])
                    if matches:
                        pattern_rows += f"<tr><td class='lbl'>{esc(label)}</td><td class='fail'>{esc(', '.join(matches))}</td></tr>\n"

            # Abuse
            abuse_rows = ""
            if abuse.get("error"):
                abuse_rows = f"<tr><td class='lbl'>Status</td><td class='neutral'>{esc(abuse['error'])}</td></tr>"
            else:
                flagged = abuse.get("is_flagged", False)
                cls = "fail" if flagged else "pass"
                abuse_rows = (
                    f"<tr><td class='lbl'>IP</td><td>{esc(abuse.get('ip'))}</td></tr>\n"
                    f"<tr><td class='lbl'>Abuse Score</td><td class='{cls}'><strong>{abuse.get('abuse_score', 0)}%</strong></td></tr>\n"
                    f"<tr><td class='lbl'>Total Reports</td><td>{abuse.get('total_reports', 0)}</td></tr>\n"
                )
                if abuse.get("isp"):
                    abuse_rows += f"<tr><td class='lbl'>ISP</td><td>{esc(abuse['isp'])}</td></tr>\n"

            threat_html = f"""
            <h2>Threat Intelligence</h2>
            <h3>Score Breakdown</h3>
            <table>{breakdown_rows if breakdown_rows else "<tr><td class='pass' colspan='2'><strong>No risk factors detected</strong></td></tr>"}</table>
            <h3>DNS Record Validation</h3>
            <table>{dns_rows}</table>
            <h3>Phishing Pattern Analysis</h3>
            <table>{pattern_rows}</table>
            <h3>AbuseIPDB Reputation</h3>
            <table>{abuse_rows}</table>"""

        # ── Assemble full HTML ──────────────────────────────────
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Email Forensic Report</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0f1117; color:#e0e0e0; padding:32px; }}
  h1 {{ color:#fff; margin-bottom:4px; }}
  .subtitle {{ color:#95a5a6; margin-bottom:24px; font-size:14px; }}
  h2 {{ color:#fff; margin:28px 0 10px; padding-bottom:6px; border-bottom:2px solid #333; }}
  h3 {{ color:#bbb; margin:18px 0 6px; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:12px; }}
  td {{ padding:6px 10px; border-bottom:1px solid #222; vertical-align:top; font-size:13px; }}
  .lbl {{ color:#95a5a6; width:180px; font-weight:600; white-space:nowrap; }}
  .pass {{ color:#2ecc71; }}
  .fail {{ color:#e74c3c; }}
  .neutral {{ color:#95a5a6; }}
  .risk-banner {{ text-align:center; padding:16px; border-radius:8px; margin-bottom:20px; }}
  .risk-score {{ font-size:36px; font-weight:bold; color:#fff; margin-right:16px; }}
  .risk-level {{ font-size:22px; font-weight:bold; color:#fff; }}
  th {{ text-align:left; padding:6px 10px; color:#95a5a6; font-size:12px; border-bottom:2px solid #333; }}
  tr:hover {{ background:#1a1d27; }}
  @media print {{
    body {{ background:#fff; color:#222; }}
    h1, h2 {{ color:#111; }}
    h3 {{ color:#555; }}
    td {{ border-bottom:1px solid #ddd; }}
    .lbl {{ color:#555; }}
    .pass {{ color:#1a8a4a; }}
    .fail {{ color:#c0392b; }}
    .neutral {{ color:#666; }}
    .risk-banner {{ print-color-adjust:exact; -webkit-print-color-adjust:exact; }}
    tr:hover {{ background:transparent; }}
  }}
</style>
</head>
<body>
<h1>Email Forensic Report</h1>
<p class="subtitle">Generated {esc(timestamp)} by Email Forensic Analyzer</p>

{risk_html}

<h2>Email Metadata</h2>
<table>{meta_rows}</table>

{header_html}

<h2>Routing Path</h2>
<table>
  <tr><th>Hop</th><th>From</th><th>By</th><th>IP</th><th>Timestamp</th></tr>
  {route_rows}
</table>

<h2>Authentication</h2>
<table>{auth_rows}</table>

{geo_html}

<h2>URLs &amp; Links</h2>
<table>
  <tr><th>#</th><th>URL</th><th>Domain</th><th>Display Text</th></tr>
  {url_rows}
</table>
{domain_html}
{url_domain_html}

<h2>Attachments</h2>
<table>
  <tr><th>#</th><th>Filename</th><th>MIME Type</th><th>Size (bytes)</th><th>MD5</th><th>SHA-256</th></tr>
  {attach_rows}
</table>

{threat_html}

<hr style="margin-top:32px;border-color:#333">
<p class="subtitle" style="margin-top:12px">End of report</p>
</body>
</html>"""


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python email_forensic_analyzer.py <path_to.eml>")
        sys.exit(1)

    analyzer = EmailForensicAnalyzer(eml_file=sys.argv[1])

    print("=== Basic Metadata ===")
    for key, value in analyzer.extract_basic_metadata().items():
        print(f"  {key}: {value}")

    print("\n=== Routing Path ===")
    for hop in analyzer.extract_routing_path():
        print(
            f"  Hop {hop['hop']}: from={hop['from']}  by={hop['by']}  "
            f"ip={hop['ip']}  timestamp={hop['timestamp']}"
        )

    print(f"\n=== Originating IP === \n  {analyzer.originating_ip}")

    print("\n=== Authentication ===")
    auth = analyzer.check_authentication()
    for key, value in auth.items():
        print(f"  {key}: {value}")

    print("\n=== IP Geolocation ===")
    ip = analyzer.originating_ip
    if ip:
        geo = analyzer.geolocate_ip(ip)
        for key, value in geo.items():
            print(f"  {key}: {value}")
    else:
        print("  No public originating IP found.")
