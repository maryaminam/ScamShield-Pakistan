"""Flask API and dashboard shell for ScamShield Pakistan."""

from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_urlsafe
from threading import Lock
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request

from email_forensic_analyzer import EmailForensicAnalyzer, _BRAND_DOMAINS
from url_analyzer import analyze_standalone_url
import ai_explainer


def _load_env_file(path: str = ".env") -> dict[str, str]:
    """Load key/value pairs from a local .env file without extra dependencies."""
    env: dict[str, str] = {}
    if not os.path.isfile(path):
        return env
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().lstrip("_")
                value = value.strip().strip('"').strip("'")
                if key and value:
                    env[key] = value
    except OSError:
        return env
    return env


BASE_DIR = Path(__file__).resolve().parent
ENV = _load_env_file(str(BASE_DIR / ".env"))
VT_API_KEY = ENV.get("VT_API") or os.environ.get("VT_API")
ABUSEIPDB_API_KEY = ENV.get("ABUSEIPDB_API") or os.environ.get("ABUSEIPDB_API")
GROQ_API_KEY = ENV.get("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")
GEMINI_API_KEY = ENV.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")


print("Loaded .env keys:", list(ENV.keys()))
print("GROQ key present:", bool(GROQ_API_KEY), "| GEMINI key present:", bool(GEMINI_API_KEY))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Demo-only activity history. It deliberately resets when Flask restarts.
ANALYSIS_HISTORY: list[dict] = []
HISTORY_LOCK = Lock()
REPORT_CACHE: dict[str, dict] = {}
REPORT_CACHE_LOCK = Lock()
_SUSPICIOUS_TLDS = {"xyz", "top", "tk", "club", "info", "work"}
# WHOIS checks can legitimately stall on slow registries. Keep the overall
# enrichment budget generous enough for optional reputation data without
# hanging the main report response.
_ENRICHMENT_BUDGET_SECONDS = 8.0


def _find_available_port(start_port: int, host: str = "127.0.0.1") -> int:
    """Find the first bindable local TCP port starting at start_port."""
    port = max(1, start_port)
    for _ in range(200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                port += 1
    raise RuntimeError("Could not find an available local port.")


def build_recommendations(risk_level: str | None, spoofing: dict, patterns: dict, auth: dict) -> list[str]:
    """Return short, actionable advice without changing the analyzer's scoring."""
    recommendations: list[str] = []
    if risk_level in {"Critical", "High"}:
        recommendations.extend([
            "Do not click any links or open attachments.",
            "Block the sender domain.",
            "Report this message to your IT or security team.",
        ])
    if auth.get("is_suspicious"):
        recommendations.append("Sender authentication failed — treat with suspicion.")
    if spoofing.get("is_spoofed"):
        recommendations.append("Sender identity could not be verified.")
    if patterns.get("credential"):
        recommendations.append("This message requests sensitive credentials — do not respond.")
    if risk_level == "Low" and not recommendations:
        recommendations.append("No immediate action required. Standard vigilance advised.")
    return recommendations or ["Review the message context before taking any action."]


def _run_email_enrichment(analyzer: EmailForensicAnalyzer, urls: list[dict] | None = None) -> tuple[dict, dict, dict, list[dict]]:
    """Run slow, optional reputation lookups concurrently with a short budget."""
    if urls is None:
        urls = []
        
    defaults = {
        "domain_rep": {"domain": None, "error": "Domain reputation lookup unavailable"},
        "dns": {
            "domain": None, "error": "DNS enrichment timed out",
            "spf": {"record": None, "exists": False},
            "dkim": {"record": None, "exists": False},
            "dmarc": {"record": None, "exists": False},
        },
        "abuse": {"ip": analyzer.originating_ip or "", "error": "AbuseIPDB enrichment timed out"},
        "url_domain_reps": [],
    }
    tasks = {
        "domain_rep": analyzer.check_domain_reputation,
        "dns": analyzer.validate_dns_records,
        "abuse": lambda: analyzer.check_ip_abuse(analyzer.originating_ip or "", api_key=ABUSEIPDB_API_KEY),
        "url_domain_reps": lambda: analyzer.check_url_domain_reputation(urls=urls, vt_api_key=VT_API_KEY, abuse_api_key=ABUSEIPDB_API_KEY),
    }
    executor = ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="scamshield-enrichment")
    futures = {executor.submit(task): name for name, task in tasks.items()}
    try:
        completed, _ = wait(futures, timeout=_ENRICHMENT_BUDGET_SECONDS)
        for future in completed:
            name = futures[future]
            try:
                defaults[name] = future.result()
            except Exception as exc:
                defaults[name] = {**defaults[name], "error": f"{name.replace('_', ' ').title()} failed: {exc}"}
    finally:
        # Any late lookup is optional; do not make the HTTP response wait for it.
        executor.shutdown(wait=False, cancel_futures=True)
    return defaults["domain_rep"], defaults["dns"], defaults["abuse"], defaults["url_domain_reps"]


def _store_report_source(raw_text: str, analysis: dict) -> str:
    """Keep a short-lived in-memory source so reports are built on demand."""
    report_id = token_urlsafe(18)
    with REPORT_CACHE_LOCK:
        REPORT_CACHE[report_id] = {"raw_text": raw_text, "analysis": analysis}
        while len(REPORT_CACHE) > 100:
            REPORT_CACHE.pop(next(iter(REPORT_CACHE)))
    return report_id


def _render_html_report(raw_text: str, analysis: dict) -> str:
    """Create the downloadable report from completed analysis, with no new lookups."""
    analyzer = EmailForensicAnalyzer(raw_text=raw_text)
    return analyzer.generate_html_report(
        metadata=analysis["metadata"], routing=analysis["routing"], auth=analysis["auth"],
        header_analysis=analysis["header_analysis"], geo=[], urls=analysis["urls"],
        attachments=analysis["attachments"], domain_rep=analysis["domain_rep"],
        threat_intel=analysis["threat_intel"],
        url_domain_reps=analysis.get("url_domain_reps"),
    )


def _analyze_email(raw_text: str) -> dict:
    """Run the established email analysis pipeline."""
    analyzer = EmailForensicAnalyzer(raw_text=raw_text)
    metadata = analyzer.extract_basic_metadata()
    routing = analyzer.extract_routing_path()
    auth = analyzer.check_authentication()
    urls = analyzer.extract_urls()
    attachments = analyzer.extract_attachments()
    spoofing = analyzer.detect_spoofing()
    header_analysis = {
        "anomalies": analyzer.detect_header_anomalies(),
        "spoofing": spoofing,
        "timestamps": analyzer.analyze_timestamps(),
        "x_headers": analyzer.extract_x_headers(),
    }
    patterns = analyzer.detect_phishing_patterns()
    domain_rep, dns, abuse, url_domain_reps = _run_email_enrichment(analyzer, urls)
    risk = analyzer.calculate_risk_score(
        auth=auth, urls=urls, attachments=attachments, domain_rep=domain_rep,
        abuse=abuse, patterns=patterns, spoofing=spoofing,
        header_anomalies=header_analysis["anomalies"],
        url_domain_reps=url_domain_reps,
    )
    threat_intel = {"dns": dns, "patterns": patterns, "abuse": abuse, "risk": risk}
    iocs = analyzer.extract_iocs(routing=routing, urls=urls, attachments=attachments, metadata=metadata)
    return {
        "metadata": metadata, "routing": routing, "auth": auth, "urls": urls,
        "attachments": attachments, "domain_rep": domain_rep, "threat_intel": threat_intel,
        "iocs": iocs, "vt_results": [],
        "spoofing": spoofing, "header_analysis": header_analysis,
        "url_domain_reps": url_domain_reps,
    }


def _append_activity(analysis_type: str, target: str, score: int, level: str) -> None:
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "type": analysis_type,
             "target": target, "risk_score": score, "threat_level": level}
    with HISTORY_LOCK:
        ANALYSIS_HISTORY.append(entry)
        del ANALYSIS_HISTORY[:-100]


def _get_email_source() -> tuple[str | None, str | None]:
    uploaded = request.files.get("email_file")
    pasted_raw = (request.form.get("raw_email") or "").strip()
    if uploaded and uploaded.filename:
        return uploaded.read().decode("utf-8", errors="replace"), uploaded.filename
    if pasted_raw:
        return pasted_raw, "Pasted email content"
    return None, None




@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze-email")
def analyze_email_api():
    raw_text, source_name = _get_email_source()
    if not raw_text:
        return jsonify({"error": "Upload a .eml file or paste raw email content first."}), 400
    try:
        result = _analyze_email(raw_text)
        risk = result["threat_intel"]["risk"]
        result["recommendations"] = build_recommendations(risk.get("level"), result["spoofing"], result["threat_intel"]["patterns"], result["auth"])
        result["report_id"] = _store_report_source(raw_text, result)
        _append_activity("email", source_name or "Email", risk.get("score", 0), risk.get("level", "Low"))
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Analysis failed: {exc}"}), 500


@app.post("/api/analyze-url")
def analyze_url_api():
    body = request.get_json(silent=True) or {}
    raw_url = str(body.get("url") or "").strip()
    if not raw_url:
        return jsonify({"error": "Enter a URL to scan."}), 400
    try:
        response = analyze_standalone_url(raw_url, vt_api_key=VT_API_KEY, abuseipdb_api_key=ABUSEIPDB_API_KEY)
        _append_activity("url_scan", response["domain"], response["risk_score"], response["threat_level"])
        return jsonify(response)
    except Exception as exc:
        return jsonify({"error": f"URL analysis failed: {exc}"}), 500


@app.post("/api/export-report")
def export_report_api():
    report_id = str((request.get_json(silent=True) or {}).get("report_id") or "")
    try:
        if report_id:
            with REPORT_CACHE_LOCK:
                saved = REPORT_CACHE.get(report_id)
            if not saved:
                return jsonify({"error": "This analysis is no longer available. Run it again before exporting."}), 404
            report = _render_html_report(saved["raw_text"], saved["analysis"])
        else:
            # Retain support for direct multipart calls to this endpoint.
            raw_text, _ = _get_email_source()
            if not raw_text:
                return jsonify({"error": "Analyze an email before exporting its report."}), 400
            report = _render_html_report(raw_text, _analyze_email(raw_text))
        return Response(report, mimetype="text/html", headers={"Content-Disposition": "attachment; filename=scamshield-forensic-report.html"})
    except Exception as exc:
        return jsonify({"error": f"Report export failed: {exc}"}), 500


@app.get("/api/dashboard-stats")
def dashboard_stats_api():
    with HISTORY_LOCK:
        history = list(ANALYSIS_HISTORY)
    counts = {level: sum(1 for item in history if item["threat_level"] == level) for level in ("Critical", "High", "Medium", "Low")}
    return jsonify({"total_analyses": len(history), "by_threat_level": counts, "recent_activity": list(reversed(history[-10:]))})


@app.post("/api/explain")
def explain_api():
    body = request.get_json(silent=True) or {}
    analysis = body.get("analysis", body)
    source = body.get("source", "email")
    normalized = ai_explainer.normalize_for_explanation(analysis, source)
    result = ai_explainer.generate_explanation(
        normalized,
        groq_api_key=GROQ_API_KEY,
        gemini_api_key=GEMINI_API_KEY,
    )
    return jsonify(result)

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Upload is too large. The maximum file size is 10 MB."}), 413


if __name__ == "__main__":
    host = os.environ.get("WEB_APP_HOST", "127.0.0.1")
    requested_port = int(os.environ.get("WEB_APP_PORT", "5000"))
    debug_mode = os.environ.get("FLASK_DEBUG", "1") not in {"0", "false", "False"}
    # Werkzeug converts some Windows bind failures into SystemExit, bypassing a
    # surrounding OSError handler. Pick a bindable port before it starts.
    port = _find_available_port(requested_port, host=host)
    if port != requested_port:
        print(f"Port {requested_port} is unavailable. Starting on http://{host}:{port} instead.")
    app.run(debug=debug_mode, host=host, port=port)
