"""Email Forensic Analyzer - header parsing, metadata extraction, routing,
authentication, geolocation, URL/attachment scanning, and domain reputation."""

import email
import email.policy
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import requests
import whois
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

# DNS resolver timeout (seconds).
_DNS_TIMEOUT = 5

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

# Risk-score weights (0–100 total budget).
_WEIGHTS = {
    "auth_fail": 25,       # any SPF/DKIM/DMARC fail or softfail
    "url_mismatch": 20,    # display/href domain mismatch
    "risky_attachment": 15, # dangerous file extension
    "young_domain": 15,    # sender domain < 30 days old
    "abuse_ip": 10,        # originating IP flagged on AbuseIPDB
    "urgency_lang": 5,     # urgency phrases in subject/body
    "credential_lang": 5,  # credential-harvesting phrases
    "impersonation": 5,    # brand impersonation keywords
}


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

        auth_results = self.msg.get("Authentication-Results")

        if auth_results is not None:
            # Collapse folded whitespace.
            auth_text = " ".join(auth_results.split())

            spf_m = _SPF_RESULT_RE.search(auth_text)
            dkim_m = _DKIM_RESULT_RE.search(auth_text)
            dmarc_m = _DMARC_RESULT_RE.search(auth_text)

            if spf_m:
                spf = spf_m.group(1).lower()
            if dkim_m:
                dkim = dkim_m.group(1).lower()
            if dmarc_m:
                dmarc = dmarc_m.group(1).lower()
        else:
            # Fallback: Received-SPF header (provides SPF only).
            received_spf = self.msg.get("Received-SPF")
            if received_spf is not None:
                m = _RECEIVED_SPF_RE.match(received_spf)
                if m:
                    spf = m.group(1).lower()

        results = {r for r in (spf, dkim, dmarc) if r is not None}
        is_suspicious = bool(results & _SUSPICIOUS_STATUSES)

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
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

                href_domain = urlparse(href).netloc.lower()
                display = tag.get_text(strip=True)

                # Check if display text itself looks like a URL with a
                # different domain (e.g. text says paypal.com, href is evil.com).
                mismatch = False
                if display.startswith(("http://", "https://")):
                    display_domain = urlparse(display).netloc.lower()
                    if display_domain and display_domain != href_domain:
                        mismatch = True

                urls.append({
                    "url": href,
                    "display_text": display or None,
                    "domain": href_domain,
                    "mismatch": mismatch,
                })

            # Also grab URLs in plain text that aren't inside <a> tags.
            visible_text = soup.get_text()
            for match in _URL_RE.findall(visible_text):
                if match not in seen:
                    seen.add(match)
                    urls.append({
                        "url": match,
                        "display_text": None,
                        "domain": urlparse(match).netloc.lower(),
                        "mismatch": False,
                    })

        elif plain_body:
            for match in _URL_RE.findall(plain_body):
                if match not in seen:
                    seen.add(match)
                    urls.append({
                        "url": match,
                        "display_text": None,
                        "domain": urlparse(match).netloc.lower(),
                        "mismatch": False,
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
            w = whois.whois(domain)
        except Exception as exc:
            return {"domain": domain, "error": f"WHOIS lookup failed: {exc}"}

        creation = w.creation_date
        # Some registrars return a list of dates.
        if isinstance(creation, list):
            creation = creation[0]

        age_days: int | None = None
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
            "registrar": w.registrar,
            "creation_date": creation_iso,
            "domain_age_days": age_days,
            "is_young": is_young,
        }


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

        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT

        def _query_txt(name: str) -> str | None:
            try:
                answers = resolver.resolve(name, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    return txt
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return None

        # SPF: TXT record on the domain itself, starts with "v=spf1"
        spf_record = None
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass

        # DKIM: try common selectors
        dkim_record = None
        for selector in ("default", "google", "selector1", "selector2",
                         "s1", "s2", "k1", "dkim", "mail"):
            result = _query_txt(f"{selector}._domainkey.{domain}")
            if result and "v=DKIM1" in result:
                dkim_record = result
                break

        # DMARC: TXT record at _dmarc.<domain>
        dmarc_record = _query_txt(f"_dmarc.{domain}")

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
        if api_key is None:
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

        score = 0
        breakdown: dict[str, tuple[int, str]] = {}

        # 1. Authentication failures
        if auth.get("is_suspicious"):
            pts = _WEIGHTS["auth_fail"]
            failures = [p for p in ("spf", "dkim", "dmarc")
                        if auth.get(p) in ("fail", "softfail")]
            score += pts
            breakdown["auth_fail"] = (pts, f"{', '.join(f.upper() for f in failures)} failed")

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
