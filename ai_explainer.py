"""AI Explanation Layer — translates pre-computed forensic findings into plain English.

Provider chain:  Groq  →  Gemini  →  deterministic template fallback.
All LLM imports happen lazily inside the call functions so a missing
SDK never prevents the rest of the application from starting.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

# ── In-process explanation cache ────────────────────────────────────
_cache: dict[str, dict] = {}

# ── Prompt constants ────────────────────────────────────────────────
_SYSTEM_PROMPT = (
    "You are explaining pre-computed email security findings to a "
    "non-technical user. Do not change the risk score or verdict — only "
    "explain it. Be concise, avoid jargon, use plain language. Output "
    "ONLY valid JSON matching the exact schema given, no markdown fences, "
    "no preamble, no extra commentary."
)

_OUTPUT_SCHEMA_INSTRUCTION = """
Return ONLY a JSON object with exactly these keys:
{
  "plain_summary": "2-3 sentence summary of what this email/URL is and why it received this risk level, written for someone with no security background",
  "key_concerns": ["short bullet", ...],
  "what_this_means": "1 paragraph explaining the practical implication",
  "recommended_actions": ["action 1", "action 2", ...]
}
Rules:
- key_concerns: max 5 items
- recommended_actions: max 4 items, imperative voice
- Do NOT add any keys beyond the four listed above
"""


# ── Trimming / normalisation ───────────────────────────────────────

def _safe_get(d: dict, *keys: str, default: Any = None) -> Any:
    """Walk nested dicts safely."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


def _build_trimmed_input(result: dict) -> dict:
    """Extract only the fields the LLM needs — keeps the prompt small."""
    risk = _safe_get(result, "threat_intel", "risk", default={})
    patterns = _safe_get(result, "threat_intel", "patterns", default={})
    dns = _safe_get(result, "threat_intel", "dns", default={})
    abuse = _safe_get(result, "threat_intel", "abuse", default={})

    return {
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "risk_breakdown": risk.get("breakdown", {}),
        "auth": {
            "spf": _safe_get(result, "auth", "spf"),
            "dkim": _safe_get(result, "auth", "dkim"),
            "dmarc": _safe_get(result, "auth", "dmarc"),
        },
        "spoofing": {
            "from_display": _safe_get(result, "spoofing", "from_display"),
            "from_address": _safe_get(result, "spoofing", "from_address"),
            "findings": [
                {"type": f.get("type"), "severity": f.get("severity"), "message": f.get("message")}
                for f in (_safe_get(result, "spoofing", "findings") or [])[:5]
            ],
        },
        "domain_rep": {
            "domain_age_days": _safe_get(result, "domain_rep", "domain_age_days"),
            "is_young": _safe_get(result, "domain_rep", "is_young"),
            "registrar": _safe_get(result, "domain_rep", "registrar"),
        },
        "patterns": {
            "urgency": (patterns.get("urgency") or [])[:5],
            "credential": (patterns.get("credential") or [])[:5],
            "impersonation": (patterns.get("impersonation") or [])[:5],
        },
        "dns": {
            "spf_exists": _safe_get(dns, "spf", "exists"),
            "dkim_exists": _safe_get(dns, "dkim", "exists"),
            "dmarc_exists": _safe_get(dns, "dmarc", "exists"),
        },
        "urls": [
            {"url": u.get("url", "")[:120], "domain": u.get("domain"), "mismatch": u.get("mismatch")}
            for u in (result.get("urls") or [])[:5]
        ],
        "attachments": [
            {"filename": a.get("filename"), "risky": a.get("risky")}
            for a in (result.get("attachments") or [])[:5]
        ],
        "abuse": {
            "abuse_score": abuse.get("abuse_score"),
            "is_flagged": abuse.get("is_flagged"),
        } if not abuse.get("error") else {"error": abuse.get("error")},
    }


def normalize_for_explanation(result: dict, source: str = "email") -> dict:
    """Normalise both email-analysis and url-analysis shapes into a common input.

    For url-analysis results (which don't have threat_intel / auth /
    spoofing at the same paths), we re-map into the shape that
    ``_build_trimmed_input`` expects.
    """
    if source == "url":
        # URL analysis returns a flat structure — wrap it to look like email
        return {
            "threat_intel": {
                "risk": {
                    "score": result.get("risk_score", 0),
                    "level": result.get("threat_level", "Low"),
                    "breakdown": {
                        ind.get("flag", "indicator"): [ind.get("points", 0), ind.get("flag", "")]
                        for ind in (result.get("indicators") or [])
                    },
                },
                "patterns": {},
                "dns": result.get("dns", {}),
                "abuse": {},
            },
            "auth": {},
            "spoofing": {},
            "domain_rep": result.get("domain_info", {}),
            "urls": [{"url": result.get("url", ""), "domain": result.get("domain"), "mismatch": False}],
            "attachments": [],
        }
    return result


# ── Deterministic fallback ─────────────────────────────────────────

def _build_fallback(result: dict) -> dict:
    """A deterministic, template-based summary when no LLM is available."""
    risk = _safe_get(result, "threat_intel", "risk", default={})
    level = risk.get("level", "Unknown")
    score = risk.get("score", 0)
    breakdown = risk.get("breakdown", {})

    # Top reasons (up to 3)
    top_reasons = []
    for signal, item in list(breakdown.items())[:3]:
        label = signal.replace("_", " ").capitalize()
        top_reasons.append(f"{label}: {item[1]}" if isinstance(item, (list, tuple)) and len(item) > 1 else label)

    reasons_text = "; ".join(top_reasons) if top_reasons else "no major risk signals were scored"

    summary = (
        f"This message was assessed as {level} risk with a score of "
        f"{score}/100. Key signals: {reasons_text}."
    )

    concerns = top_reasons[:5] if top_reasons else ["No specific concerns were flagged."]

    if level in ("Critical", "High"):
        meaning = (
            "This message shows strong indicators of being malicious or "
            "deceptive. Interacting with it — clicking links, opening "
            "attachments, or replying — could compromise your account or device."
        )
        actions = [
            "Do not click any links or open attachments.",
            "Report this message to your IT or security team.",
            "Block the sender.",
            "Delete the message.",
        ]
    elif level == "Medium":
        meaning = (
            "This message has some characteristics that could indicate a "
            "phishing attempt, but it is not conclusive. Exercise caution."
        )
        actions = [
            "Verify the sender's identity through a separate channel.",
            "Avoid clicking links until you confirm they are legitimate.",
            "Report the message if anything seems unusual.",
        ]
    else:
        meaning = (
            "This message does not show significant signs of being "
            "malicious. Standard email vigilance is still recommended."
        )
        actions = [
            "No immediate action required.",
            "Continue to exercise normal caution with unsolicited messages.",
        ]

    return {
        "plain_summary": summary,
        "key_concerns": concerns,
        "what_this_means": meaning,
        "recommended_actions": actions,
        "provider": "fallback",
    }


# ── LLM provider calls ────────────────────────────────────────────

'''
def _call_groq(user_prompt: str, api_key: str) -> str:
    """Call Groq's chat completions API. Returns raw response text."""
    from groq import Groq  # lazy import

    client = Groq(api_key=api_key, timeout=10.0)
    completion = client.chat.completions.create(
        model="qwen/qwen3.6-27b",
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.3,
        max_tokens=800,
    )
    return completion.choices[0].message.content or ""
'''

def _call_groq(user_prompt: str, api_key: str) -> str:
    from groq import Groq
    client = Groq(api_key=api_key, timeout=10.0)
    completion = client.chat.completions.create(
        model="openai/gpt-oss-20b",   # swap off the preview qwen model
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.3,
        max_tokens=1500,   # give it more headroom to finish the JSON
    )
    return completion.choices[0].message.content or ""


def _call_gemini(user_prompt: str, api_key: str) -> str:
    """Call Google Gemini via the google-genai SDK. Returns raw response text."""
    from google import genai  # lazy import

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=f"{_SYSTEM_PROMPT}\n\n{user_prompt}",
        config=genai.types.GenerateContentConfig(
            temperature=0.3,
            max_output_tokens=800,
            response_mime_type="application/json",
        ),
    )
    return response.text or ""
    


def _parse_llm_response(raw_text: str) -> dict:
    """Parse the LLM's raw text into the expected dict schema.

    Raises ``json.JSONDecodeError`` if the output is not valid JSON, and
    ``ValueError`` if required keys are missing.
    """
    data = json.loads(raw_text)

    # Validate required keys
    for key in ("plain_summary", "key_concerns", "what_this_means", "recommended_actions"):
        if key not in data:
            raise ValueError(f"LLM response missing required key: {key}")

    # Enforce length limits
    data["key_concerns"] = list(data["key_concerns"])[:5]
    data["recommended_actions"] = list(data["recommended_actions"])[:4]
    return data


# ── Main entry point ───────────────────────────────────────────────

def generate_explanation(
    analysis_result: dict,
    *,
    groq_api_key: str | None = None,
    gemini_api_key: str | None = None,
) -> dict:
    """Produce a human-readable explanation of pre-computed forensic findings.

    Provider chain:  Groq  →  Gemini  →  deterministic fallback.
    Results are cached in-process by a SHA-256 hash of the trimmed input.
    """
    trimmed = _build_trimmed_input(analysis_result)
    cache_key = hashlib.sha256(
        json.dumps(trimmed, sort_keys=True, default=str).encode()
    ).hexdigest()

    if cache_key in _cache:
        return _cache[cache_key]

    user_prompt = (
        "Here are the pre-computed security findings:\n"
        + json.dumps(trimmed, indent=2, default=str)
        + "\n\n"
        + _OUTPUT_SCHEMA_INSTRUCTION
    )

    # ── Try Groq ────────────────────────────────────────────────
    if groq_api_key:
        try:
            raw = _call_groq(user_prompt, groq_api_key)
            explanation = _parse_llm_response(raw)
            explanation["provider"] = "groq"
            _cache[cache_key] = explanation
            return explanation
        except json.JSONDecodeError:
            log.warning("Groq returned non-JSON output; falling through to Gemini.")
        except Exception as exc:
            log.warning("Groq call failed (%s); falling through to Gemini.", exc)

    # ── Try Gemini ──────────────────────────────────────────────
    if gemini_api_key:
        try:
            raw = _call_gemini(user_prompt, gemini_api_key)
            explanation = _parse_llm_response(raw)
            explanation["provider"] = "gemini"
            _cache[cache_key] = explanation
            return explanation
        except json.JSONDecodeError:
            log.warning("Gemini returned non-JSON output; falling through to fallback.")
        except Exception as exc:
            log.warning("Gemini call failed (%s); falling through to fallback.", exc)

    # ── Deterministic fallback ──────────────────────────────────
    fallback = _build_fallback(analysis_result)
    _cache[cache_key] = fallback
    return fallback
