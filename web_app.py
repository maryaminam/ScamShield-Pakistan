"""FastAPI async dashboard for ScamShield Pakistan."""

from __future__ import annotations

import asyncio
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_urlsafe

import threading

import json as _json

import uvicorn
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from email_forensic_analyzer import EmailForensicAnalyzer, _BRAND_DOMAINS
from url_analyzer import async_analyze_standalone_url
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

app = FastAPI(title="ScamShield Pakistan")


@app.on_event("startup")
async def _warm_nlp_classifier():
    """Pre-load the NLP model in a background thread so the first request
    doesn't pay the 15–30 s model-loading cost.  Does NOT block server
    readiness — the warm-up runs alongside accepting connections."""
    def _load():
        try:
            from nlp_phishing_classifier import _get_classifier
            _get_classifier()
        except Exception as exc:
            print(f"[NLP warmup] Failed: {exc}")

    t = threading.Thread(target=_load, daemon=True, name="nlp-warmup")
    t.start()
    # Don't await — let it run alongside the first requests.
    print("[NLP warmup] Model loading in background thread…")


# Serve static files (app.js, CSS, etc.)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Demo-only activity history. It deliberately resets when the server restarts.
ANALYSIS_HISTORY: list[dict] = []
REPORT_CACHE: dict[str, dict] = {}
_SUSPICIOUS_TLDS = {"xyz", "top", "tk", "club", "info", "work"}
# WHOIS checks can legitimately stall on slow registries. Keep the overall
# enrichment budget generous enough for optional reputation data without
# hanging the main report response.
_ENRICHMENT_BUDGET_SECONDS = 8.0

# ── Security: Rate Limiting state ──────────────────────────────────────────
_RATE_LIMITS: dict[str, list[float]] = {}


def _is_rate_limited(ip: str, max_reqs: int = 30, window: int = 60) -> bool:
    """Simple sliding window rate limiter per IP address."""
    now = time.time()
    history = _RATE_LIMITS.setdefault(ip, [])
    # Keep requests within the window
    history[:] = [t for t in history if now - t < window]
    if len(history) >= max_reqs:
        return True
    history.append(now)
    return False


# ── Middleware: security headers ───────────────────────────────────────────
@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    """Apply standard web security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    )
    return response


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


async def _async_run_email_enrichment(
    analyzer: EmailForensicAnalyzer, urls: list[dict] | None = None,
) -> tuple[dict, dict, dict, list[dict]]:
    """Run slow, optional reputation lookups concurrently using asyncio.gather."""
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

    # Create all 4 enrichment tasks as concurrent coroutines
    tasks = {
        "domain_rep": asyncio.create_task(analyzer.async_check_domain_reputation()),
        "dns": asyncio.create_task(analyzer.async_validate_dns_records()),
        "abuse": asyncio.create_task(
            analyzer.async_check_ip_abuse(analyzer.originating_ip or "", api_key=ABUSEIPDB_API_KEY)
        ),
        "url_domain_reps": asyncio.create_task(
            analyzer.async_check_url_domain_reputation(
                urls=urls, vt_api_key=VT_API_KEY, abuse_api_key=ABUSEIPDB_API_KEY,
            )
        ),
    }

    # Wait for all tasks with a budget, handling per-task failures
    done, pending = await asyncio.wait(
        tasks.values(), timeout=_ENRICHMENT_BUDGET_SECONDS,
    )

    # Cancel any tasks that exceeded the budget
    for task in pending:
        task.cancel()
    # Give cancelled tasks a brief grace period to clean up, then abandon.
    # Blocking threads (asyncio.to_thread WHOIS) can't be killed, so we
    # cap the cleanup wait at 2 s to avoid holding up the response.
    if pending:
        await asyncio.wait(pending, timeout=2.0)

    # Map results back by identity
    for name, task in tasks.items():
        if task in done:
            try:
                defaults[name] = task.result()
            except Exception as exc:
                defaults[name] = {
                    **defaults[name],
                    "error": f"{name.replace('_', ' ').title()} failed: {exc}",
                }

    return defaults["domain_rep"], defaults["dns"], defaults["abuse"], defaults["url_domain_reps"]


def _store_report_source(raw_text: str, analysis: dict) -> str:
    """Keep a short-lived in-memory source so reports are built on demand."""
    report_id = token_urlsafe(18)
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


async def _async_analyze_email(raw_text: str) -> dict:
    """Run the established email analysis pipeline with async enrichment."""
    analyzer = EmailForensicAnalyzer(raw_text=raw_text)

    # All CPU-bound parsing steps are synchronous and fast
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

    # Run NLP classification and async enrichment in parallel.
    # NLP is CPU-bound (thread pool); enrichment is I/O-bound (event loop).
    # They overlap so the total wall time ≈ max(NLP, enrichment) instead of
    # the sum of both.
    nlp_task = asyncio.create_task(
        asyncio.to_thread(analyzer.detect_phishing_patterns)
    )
    enrichment_task = asyncio.create_task(
        _async_run_email_enrichment(analyzer, urls)
    )
    patterns, (domain_rep, dns, abuse, url_domain_reps) = await asyncio.gather(
        nlp_task, enrichment_task,
    )

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
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "type": analysis_type,
        "target": target, "risk_score": score, "threat_level": level,
    }
    ANALYSIS_HISTORY.append(entry)
    del ANALYSIS_HISTORY[:-100]


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/api/analyze-email")
async def analyze_email_api(
    request: Request,
    email_file: UploadFile | None = File(None),
    raw_email: str = Form(""),
):
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return JSONResponse(
            {"error": "Too many requests. Please try again later."}, status_code=429,
        )

    # Determine the email source
    raw_text: str | None = None
    source_name: str | None = None

    if email_file is not None and email_file.filename:
        content = await email_file.read()
        raw_text = content.decode("utf-8", errors="replace")
        source_name = email_file.filename
    elif raw_email.strip():
        raw_text = raw_email.strip()
        source_name = "Pasted email content"

    if not raw_text:
        return JSONResponse(
            {"error": "Upload a .eml file or paste raw email content first."}, status_code=400,
        )

    try:
        result = await _async_analyze_email(raw_text)
        risk = result["threat_intel"]["risk"]
        result["recommendations"] = build_recommendations(
            risk.get("level"), result["spoofing"], result["threat_intel"]["patterns"], result["auth"],
        )
        result["report_id"] = _store_report_source(raw_text, result)
        _append_activity("email", source_name or "Email", risk.get("score", 0), risk.get("level", "Low"))
        return result
    except Exception as exc:
        return JSONResponse({"error": f"Analysis failed: {exc}"}, status_code=500)


# ── SSE progress-streaming endpoint ───────────────────────────────────
def _sse_event(event: str, data: dict | str) -> str:
    """Format a Server-Sent Events message."""
    payload = data if isinstance(data, str) else _json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


@app.post("/api/analyze-email-stream")
async def analyze_email_stream(
    request: Request,
    email_file: UploadFile | None = File(None),
    raw_email: str = Form(""),
):
    """Analyze an email and stream progress updates via SSE.

    Event types:
        progress — ``{phase, label, detail}`` as each analysis step finishes.
        result   — the complete analysis dict (same shape as ``/api/analyze-email``).
        error    — ``{error: str}`` if the analysis fails.
    """
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return JSONResponse(
            {"error": "Too many requests. Please try again later."}, status_code=429,
        )

    raw_text: str | None = None
    source_name: str | None = None

    if email_file is not None and email_file.filename:
        content = await email_file.read()
        raw_text = content.decode("utf-8", errors="replace")
        source_name = email_file.filename
    elif raw_email.strip():
        raw_text = raw_email.strip()
        source_name = "Pasted email content"

    if not raw_text:
        return JSONResponse(
            {"error": "Upload a .eml file or paste raw email content first."}, status_code=400,
        )

    async def event_stream():
        try:
            analyzer = EmailForensicAnalyzer(raw_text=raw_text)

            # Phase 1 — Metadata & routing (fast, synchronous)
            yield _sse_event("progress", {"phase": "metadata", "label": "Parsing headers",
                                           "detail": "Extracting sender, subject, dates, and routing path"})
            metadata = analyzer.extract_basic_metadata()
            routing = analyzer.extract_routing_path()

            # Phase 2 — Authentication
            yield _sse_event("progress", {"phase": "auth", "label": "Verifying authentication",
                                           "detail": "Checking SPF, DKIM, and DMARC alignment"})
            auth = analyzer.check_authentication()

            # Phase 3 — URLs & attachments
            yield _sse_event("progress", {"phase": "urls", "label": "Scanning links and attachments",
                                           "detail": "Detecting display/href mismatches and risky file types"})
            urls = analyzer.extract_urls()
            attachments = analyzer.extract_attachments()

            # Phase 4 — Spoofing, headers, and NLP patterns
            yield _sse_event("progress", {"phase": "patterns", "label": "Analyzing language and identity",
                                           "detail": "Checking spoofing, phishing language, and ML classification"})
            spoofing = analyzer.detect_spoofing()
            header_analysis = {
                "anomalies": analyzer.detect_header_anomalies(),
                "spoofing": spoofing,
                "timestamps": analyzer.analyze_timestamps(),
                "x_headers": analyzer.extract_x_headers(),
            }

            # Run NLP + enrichment in parallel
            yield _sse_event("progress", {"phase": "enrichment", "label": "Enriching reputation data",
                                           "detail": "Running ML classification and DNS/WHOIS lookups in parallel"})
            nlp_task = asyncio.create_task(
                asyncio.to_thread(analyzer.detect_phishing_patterns)
            )
            enrichment_task = asyncio.create_task(
                _async_run_email_enrichment(analyzer, urls)
            )
            patterns, (domain_rep, dns, abuse, url_domain_reps) = await asyncio.gather(
                nlp_task, enrichment_task,
            )

            # Phase 6 — Risk scoring
            yield _sse_event("progress", {"phase": "scoring", "label": "Calculating risk score",
                                           "detail": "Combining all signals into a 0–100 weighted score"})
            risk = analyzer.calculate_risk_score(
                auth=auth, urls=urls, attachments=attachments, domain_rep=domain_rep,
                abuse=abuse, patterns=patterns, spoofing=spoofing,
                header_anomalies=header_analysis["anomalies"],
                url_domain_reps=url_domain_reps,
            )
            threat_intel = {"dns": dns, "patterns": patterns, "abuse": abuse, "risk": risk}
            iocs = analyzer.extract_iocs(routing=routing, urls=urls, attachments=attachments, metadata=metadata)

            result = {
                "metadata": metadata, "routing": routing, "auth": auth, "urls": urls,
                "attachments": attachments, "domain_rep": domain_rep, "threat_intel": threat_intel,
                "iocs": iocs, "vt_results": [],
                "spoofing": spoofing, "header_analysis": header_analysis,
                "url_domain_reps": url_domain_reps,
            }
            result["recommendations"] = build_recommendations(
                risk.get("level"), result["spoofing"], result["threat_intel"]["patterns"], result["auth"],
            )
            result["report_id"] = _store_report_source(raw_text, result)
            _append_activity("email", source_name or "Email", risk.get("score", 0), risk.get("level", "Low"))

            yield _sse_event("result", result)

        except Exception as exc:
            yield _sse_event("error", {"error": f"Analysis failed: {exc}"})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/analyze-url")
async def analyze_url_api(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip, max_reqs=20):
        return JSONResponse(
            {"error": "Too many requests. Please try again later."}, status_code=429,
        )

    body = await request.json() if await request.body() else {}
    raw_url = str(body.get("url") or "").strip()
    if not raw_url:
        return JSONResponse({"error": "Enter a URL to scan."}, status_code=400)

    try:
        response = await async_analyze_standalone_url(
            raw_url, vt_api_key=VT_API_KEY, abuseipdb_api_key=ABUSEIPDB_API_KEY,
        )
        _append_activity("url_scan", response["domain"], response["risk_score"], response["threat_level"])
        return response
    except Exception as exc:
        return JSONResponse({"error": f"URL analysis failed: {exc}"}, status_code=500)


@app.post("/api/export-report")
async def export_report_api(
    request: Request,
    email_file: UploadFile | None = File(None),
    raw_email: str = Form(""),
    report_id: str | None = None,
):
    # Try to read report_id from JSON body if present
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json() if await request.body() else {}
        report_id = str(body.get("report_id") or "")

    try:
        if report_id:
            saved = REPORT_CACHE.get(report_id)
            if not saved:
                return JSONResponse(
                    {"error": "This analysis is no longer available. Run it again before exporting."},
                    status_code=404,
                )
            report = _render_html_report(saved["raw_text"], saved["analysis"])
        else:
            # Retain support for direct multipart calls to this endpoint.
            raw_text: str | None = None
            if email_file is not None and email_file.filename:
                content = await email_file.read()
                raw_text = content.decode("utf-8", errors="replace")
            elif raw_email.strip():
                raw_text = raw_email.strip()

            if not raw_text:
                return JSONResponse(
                    {"error": "Analyze an email before exporting its report."}, status_code=400,
                )
            report = _render_html_report(raw_text, await _async_analyze_email(raw_text))

        return Response(
            content=report,
            media_type="text/html",
            headers={"Content-Disposition": "attachment; filename=scamshield-forensic-report.html"},
        )
    except Exception as exc:
        return JSONResponse({"error": f"Report export failed: {exc}"}, status_code=500)


@app.get("/api/dashboard-stats")
async def dashboard_stats_api():
    history = list(ANALYSIS_HISTORY)
    counts = {
        level: sum(1 for item in history if item["threat_level"] == level)
        for level in ("Critical", "High", "Medium", "Low")
    }
    return {
        "total_analyses": len(history),
        "by_threat_level": counts,
        "recent_activity": list(reversed(history[-10:])),
    }


@app.post("/api/explain")
async def explain_api(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip, max_reqs=10):
        return JSONResponse(
            {"error": "Too many requests to AI explainer. Please wait."}, status_code=429,
        )

    body = await request.json() if await request.body() else {}
    analysis = body.get("analysis", body)
    source = body.get("source", "email")
    normalized = ai_explainer.normalize_for_explanation(analysis, source)
    result = await ai_explainer.async_generate_explanation(
        normalized,
        groq_api_key=GROQ_API_KEY,
        gemini_api_key=GEMINI_API_KEY,
    )
    return result


# ── Error handler for oversized uploads ────────────────────────────────────
@app.exception_handler(413)
async def too_large_handler(request: Request, exc):
    return JSONResponse(
        {"error": "Upload is too large. The maximum file size is 10 MB."},
        status_code=413,
    )


if __name__ == "__main__":
    host = os.environ.get("WEB_APP_HOST", "127.0.0.1")
    requested_port = int(os.environ.get("WEB_APP_PORT", "5000"))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") not in {"0", "false", "False"}
    port = _find_available_port(requested_port, host=host)
    if port != requested_port:
        print(f"Port {requested_port} is unavailable. Starting on http://{host}:{port} instead.")
    uvicorn.run(app, host=host, port=port, log_level="info")
