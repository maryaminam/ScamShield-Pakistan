"""Email Forensic Analyzer - header parsing, metadata extraction, and routing analysis."""

import email
import email.policy
import ipaddress
import re
from pathlib import Path

import requests

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
