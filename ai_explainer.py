"""AI Explanation Layer — translates pre-computed forensic findings into plain English.

Provider chain:  Groq  →  Gemini  →  deterministic template fallback.
All LLM imports happen lazily inside the call functions so a missing
SDK never prevents the rest of the application from starting.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from typing import Any

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


# ── Pydantic schema for strict LLM output validation ─────────────
class ExplanationResponse(BaseModel):
    """Strict schema that every LLM response must satisfy."""

    plain_summary: str = Field(
        ...,
        description=(
            "2-3 sentence summary of what this analyzed item (email or URL) is "
            "and why it received this risk level, written for someone with no "
            "security background"
        ),
    )
    key_concerns: list[str] = Field(
        ...,
        max_length=5,
        description="Short bullets referencing specific names, domains, or phrases from the input",
    )
    what_this_means: str = Field(
        ...,
        description="1 paragraph explaining the practical implication for the user",
    )
    recommended_actions: list[str] = Field(
        ...,
        max_length=4,
        description="Imperative-voice actions the user should take",
    )


# Hand-crafted JSON schema (no $ref, no additionalProperties) — compatible
# with Gemini ``response_schema`` and Groq ``response_format``.
_JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "plain_summary": {
            "type": "string",
            "description": (
                "2-3 sentence summary of what this analyzed item is and why "
                "it received this risk level, written for a non-technical user"
            ),
        },
        "key_concerns": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 5,
            "description": (
                "Short bullets referencing specific names, domains, or phrases"
            ),
        },
        "what_this_means": {
            "type": "string",
            "description": "1 paragraph explaining the practical implication",
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 4,
            "description": "Imperative-voice actions the user should take",
        },
    },
    "required": [
        "plain_summary",
        "key_concerns",
        "what_this_means",
        "recommended_actions",
    ],
    "additionalProperties": False,
}

# ── In-process explanation cache ────────────────────────────────────
_cache: dict[str, dict] = {}

# ── Prompt constants ────────────────────────────────────────────────
_SYSTEM_PROMPT = (
    "You are explaining pre-computed security findings (either from an email or a standalone URL scan) to a "
    "non-technical user. Do not change the risk score or verdict — only "
    "explain it.\n\n"
    "Be concise and avoid jargon, but do NOT be vague or generic. Always "
    "name the specific sender address, domain names, display names, and "
    "flagged phrases from the input data — never write generic filler like "
    "'this shows some concerning signs' or 'there are authentication "
    "issues.' Write the way a helpful colleague would explain it, pointing "
    "at exact details: who it claims to be from, what destination a link leads to, what "
    "specific link or word triggered concern.\n\n"
    "Output ONLY valid JSON matching the exact schema given, no markdown "
    "fences, no preamble, no extra commentary."
)

_OUTPUT_SCHEMA_INSTRUCTION = """
Return ONLY a JSON object conforming to the provided response_schema.
The SDK enforces the exact key structure — do NOT add extra keys.

Guidance for content quality:
- key_concerns: max 5 items
- recommended_actions: max 4 items, imperative voice
- Every bullet and sentence should reference an actual name, domain, or
  phrase from the input — not a category label
- If ml_scores are provided in the input, mention any high-confidence ML
  detections (social manipulation, urgency, etc.) in the explanation

Example of the specificity expected:
BAD:  "This item has some authentication issues and a suspicious sender."
GOOD: "This email claims to be from 'Intima\u00e7\u00e3o eletr\u00f4nica' but was actually
       sent through cartorio02@uorak.com, and Microsoft's own systems
       flagged that the domain shown to you doesn't match the domain that
       actually sent it — a classic spoofing pattern."
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
            "compauth": _safe_get(result, "auth", "compauth"),
            "compauth_reason": _safe_get(result, "auth", "compauth_reason"),
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
            "ml_scores": patterns.get("ml_scores", {}),
            "ml_flagged": patterns.get("ml_flagged", []),
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
        "header_anomalies": [
            a for a in (_safe_get(result, "header_analysis", "anomalies", "anomalies") or [])[:5]
        ],
        "url_domain_reps": [
            {"domain": r.get("domain"), "domain_age_days": r.get("domain_age_days"),
             "is_young": r.get("is_young")}
            for r in (result.get("url_domain_reps") or [])[:3]
        ],
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
                "dns": {},
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

def _call_groq(user_prompt: str, api_key: str) -> str:
    """Call Groq's chat completions API with structured output.

    Uses ``response_format`` with an explicit JSON schema so the model is
    constrained to produce the exact keys we expect, eliminating
    ``JSONDecodeError`` and missing-key failures.
    """
    from groq import Groq  # lazy import

    client = Groq(api_key=api_key, timeout=10.0)
    completion = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "explanation_response",
                "strict": True,
                "schema": _JSON_SCHEMA,
            },
        },
        temperature=0.6,   # higher temp for natural phrasing; facts are
                           # constrained by the JSON input, not the model
        max_tokens=1500,
    )
    return completion.choices[0].message.content or ""


def _call_gemini(user_prompt: str, api_key: str) -> str:
    """Call Google Gemini via the google-genai SDK with ``response_schema``.

    The explicit schema forces Gemini to emit JSON conforming exactly to
    :class:`ExplanationResponse`, eliminating hallucinated extra keys or
    malformed output.
    """
    from google import genai  # lazy import

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=f"{_SYSTEM_PROMPT}\n\n{user_prompt}",
        config=genai.types.GenerateContentConfig(
            max_output_tokens=800,
            response_mime_type="application/json",
            response_schema=_JSON_SCHEMA,
            # temperature/top_p/top_k removed — Gemini 3.6 Flash no longer
            # accepts these sampling params; passing them can error or be ignored
        ),
    )
    return response.text or ""
    


def _parse_llm_response(raw_text: str) -> dict:
    """Parse and strictly validate the LLM's JSON output.

    1. ``json.loads`` — rejects non-JSON output.
    2. ``ExplanationResponse.model_validate`` — Pydantic enforces types,
       required keys, and ``max_length`` constraints on lists.

    Raises ``json.JSONDecodeError`` for non-JSON and ``pydantic.ValidationError``
    (which subclasses ``ValueError``) for schema violations.
    """
    data = json.loads(raw_text)

    # Pydantic strict validation — catches missing keys, wrong types, and
    # list-length violations in a single pass.
    validated = ExplanationResponse.model_validate(data)
    return validated.model_dump()


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


# ── Async entry point ─────────────────────────────────────────────

async def async_generate_explanation(
    analysis_result: dict,
    *,
    groq_api_key: str | None = None,
    gemini_api_key: str | None = None,
) -> dict:
    """Async version of generate_explanation.

    The blocking Groq/Gemini SDK calls are offloaded to threads via
    asyncio.to_thread so the event loop is never blocked.
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

    # ── Try Groq (blocking SDK → thread) ───────────────────────
    if groq_api_key:
        try:
            raw = await asyncio.to_thread(_call_groq, user_prompt, groq_api_key)
            explanation = _parse_llm_response(raw)
            explanation["provider"] = "groq"
            _cache[cache_key] = explanation
            return explanation
        except json.JSONDecodeError:
            log.warning("Groq returned non-JSON output; falling through to Gemini.")
        except Exception as exc:
            log.warning("Groq call failed (%s); falling through to Gemini.", exc)

    # ── Try Gemini (blocking SDK → thread) ──────────────────────
    if gemini_api_key:
        try:
            raw = await asyncio.to_thread(_call_gemini, user_prompt, gemini_api_key)
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
