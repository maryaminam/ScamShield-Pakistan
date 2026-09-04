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
import re
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
- Use the provided "signal_strength" field to decide emphasis:
  * "conclusive" signals are hard evidence — lead with these
  * "strong" signals are reliable but can have benign explanations
  * "moderate" signals are suspicious context
  * "weak" signals are minor — mention only if they add useful detail

Example of the specificity expected:
BAD:  "This item has some authentication issues and a suspicious sender."
GOOD: "This email claims to be from 'Intima\u00e7\u00e3o eletr\u00f4nica' but was actually
       sent through cartorio02@uorak.com, and Microsoft's own systems
       flagged that the domain shown to you doesn't match the domain that
       actually sent it — a classic spoofing pattern."
"""

# Classify each scoring signal so the LLM knows which findings are hard
# evidence vs circumstantial context. Keys match the risk_breakdown dict.
_SIGNAL_STRENGTH: dict[str, str] = {
    # Conclusive: direct compromise evidence
    "auth_fail": "conclusive",
    "compauth_fail": "conclusive",
    "vt_url_malicious": "conclusive",
    "risky_attachment": "conclusive",
    "homograph_domain": "conclusive",
    # Strong: very suspicious but occasionally benign
    "spoofing": "strong",
    "url_mismatch": "strong",
    "impersonation": "strong",
    "abuse_ip": "strong",
    "abuseip_url": "strong",
    "young_domain": "strong",
    "young_url_domain": "strong",
    "attachment_brand_spoof": "strong",
    # Moderate: context that supports a conclusion
    "header_anomaly": "moderate",
    "urgency_lang": "moderate",
    "credential_lang": "moderate",
    "url_path_brand": "moderate",
    "url_path_lure": "moderate",
    # Weak: minor or often benign signals
    "ml_manipulation": "weak",
}

# Tone guidance appended to the user prompt based on the risk level.
_RISK_TONE: dict[str, str] = {
    "Critical": (
        "Tone: urgent and direct. The user is likely looking at an active "
        "threat. Lead with the most important action, avoid hedging, and "
        "make clear that interaction is dangerous."
    ),
    "High": (
        "Tone: serious and action-oriented. Explain why this is likely "
        "malicious and give concrete steps the user should take now."
    ),
    "Medium": (
        "Tone: cautious and investigative. Explain what is suspicious and "
        "what the user should verify before trusting the item."
    ),
    "Low": (
        "Tone: reassuring and brief. Confirm that no major red flags were "
        "found while still encouraging normal caution."
    ),
}

# One-shot examples for email and URL scans, one per risk level.
# All domains and senders are deliberately fake placeholders.
_ONE_SHOT_EXAMPLES = """
One-shot examples (all domains/senders are fake placeholders):

--- EMAIL — Critical ---
Input findings summary:
- Source: email
- Risk: 92/100 Critical
- From display: "MegaBank Security"
- From address: alert@megabank-secure.example.com
- SPF/DKIM/DMARC: all fail
- URLs: https://evil-example.com/verify (display text said megabank.com)
- Attachment: invoice.exe (risky executable)
- Signal strength: auth_fail=conclusive, url_mismatch=strong, risky_attachment=conclusive

Expected JSON output:
{
  "plain_summary": "This email pretends to be from MegaBank Security but was sent from alert@megabank-secure.example.com, a domain unrelated to the real bank. SPF, DKIM and DMARC all failed, the link shown as megabank.com actually leads to evil-example.com, and it includes an executable file named invoice.exe — all classic signs of a phishing attack.",
  "key_concerns": [
    "SPF, DKIM and DMARC all failed for megabank-secure.example.com",
    "Link display said megabank.com but href pointed to evil-example.com",
    "Executable attachment invoice.exe could install malware"
  ],
  "what_this_means": "This is almost certainly a phishing email designed to steal credentials or infect your device. The sender, link, and attachment are all independently suspicious.",
  "recommended_actions": [
    "Do not click the link or open the attachment.",
    "Report the email to your IT/security team immediately.",
    "Delete the message."
  ]
}

--- EMAIL — Medium ---
Input findings summary:
- Source: email
- Risk: 38/100 Medium
- From display: "IT Helpdesk"
- From address: support@company-it.example.com
- Domain age: 5 days
- Phishing patterns: "immediate action required", "verify your password"
- Signal strength: young_domain=strong, urgency_lang=moderate, credential_lang=moderate

Expected JSON output:
{
  "plain_summary": "This email claims to be from an IT helpdesk at support@company-it.example.com. The domain was registered only 5 days ago, and the message uses urgency phrases like 'immediate action required' and asks you to 'verify your password'.",
  "key_concerns": [
    "Sender domain company-it.example.com is only 5 days old",
    "Subject/body uses urgency phrase 'immediate action required'",
    "Contains credential-harvesting phrase 'verify your password'"
  ],
  "what_this_means": "These are common phishing tactics, but they could also appear in a legitimate new IT notice. Confirm through a separate channel before acting.",
  "recommended_actions": [
    "Contact your real IT team through a known phone number or ticket system.",
    "Do not enter your password until the sender is verified.",
    "Check the sender's domain age and compare it to your organization's official domain."
  ]
}

--- EMAIL — Low ---
Input findings summary:
- Source: email
- Risk: 5/100 Low
- From display: "Example Newsletter"
- From address: hello@legitimate-example.com
- SPF/DKIM/DMARC: all pass
- No suspicious patterns, no URL mismatches, no risky attachments

Expected JSON output:
{
  "plain_summary": "This email from hello@legitimate-example.com passed SPF, DKIM and DMARC checks, and no suspicious links, language, or attachments were detected.",
  "key_concerns": [
    "No major risk signals were found."
  ],
  "what_this_means": "The message appears legitimate based on the available forensic checks. Standard caution with unsolicited email is still recommended.",
  "recommended_actions": [
    "No immediate action required.",
    "Continue to exercise normal caution with links and attachments."
  ]
}

--- URL — Critical ---
Input findings summary:
- Source: url
- Risk: 88/100 Critical
- URL: https://paypa1-secure.example.com/login.php
- Indicators: punycode/homograph domain, flagged by VirusTotal, brand keyword 'paypal' on non-official domain
- Signal strength: homograph_domain=conclusive, vt_url_malicious=conclusive

Expected JSON output:
{
  "plain_summary": "The URL https://paypa1-secure.example.com/login.php uses a look-alike domain designed to imitate PayPal. VirusTotal has flagged it as malicious, and the domain itself is not an official PayPal domain.",
  "key_concerns": [
    "Domain paypa1-secure.example.com is a homograph/look-alike of PayPal",
    "URL is flagged as malicious by VirusTotal",
    "Brand keyword 'paypal' appears on a non-official domain"
  ],
  "what_this_means": "This is a fake login page created to steal PayPal credentials. Visiting it could result in account compromise.",
  "recommended_actions": [
    "Do not visit the URL or enter any credentials.",
    "Report the URL to your security team or browser safe-browsing service.",
    "If you already entered credentials, change your password immediately."
  ]
}

--- URL — Medium ---
Input findings summary:
- Source: url
- Risk: 42/100 Medium
- URL: http://fake-shop.example.com/paypal/login.html
- Indicators: brand keyword 'paypal' in path, does not use HTTPS, domain registered recently
- Signal strength: url_path_brand=moderate, no HTTPS=moderate, young_domain=strong

Expected JSON output:
{
  "plain_summary": "The URL http://fake-shop.example.com/paypal/login.html mentions 'paypal' in its path but is hosted on fake-shop.example.com, not PayPal. It also does not use HTTPS and the domain was registered recently.",
  "key_concerns": [
    "Path contains brand keyword 'paypal' but domain is fake-shop.example.com",
    "Connection is not encrypted (no HTTPS)",
    "Domain was registered recently"
  ],
  "what_this_means": "These signs are suspicious and suggest a possible phishing page, though some legitimate sites can also be newly registered. Treat it with caution until verified.",
  "recommended_actions": [
    "Do not enter login or payment information on this page.",
    "Navigate to the real site by typing the known official URL manually.",
    "Check the domain registration date and SSL certificate if you must visit."
  ]
}

--- URL — Low ---
Input findings summary:
- Source: url
- Risk: 8/100 Low
- URL: https://legitimate-example.com/products
- Indicators: none
- Domain age: several years old, HTTPS enabled

Expected JSON output:
{
  "plain_summary": "The URL https://legitimate-example.com/products uses HTTPS, the domain is several years old, and no suspicious indicators such as brand misuse, redirects, or blocklist flags were found.",
  "key_concerns": [
    "No high-risk URL indicators were found."
  ],
  "what_this_means": "This appears to be a normal, legitimate webpage. Continue to use standard caution when entering personal information online.",
  "recommended_actions": [
    "No immediate action required.",
    "Use normal caution before entering passwords or payment details."
  ]
}
"""


# ── Trimming / normalisation ───────────────────────────────────────

def _safe_get(d: dict, *keys: str, default: Any = None) -> Any:
    """Walk nested dicts safely."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


def _build_trimmed_input(result: dict, source: str = "email") -> dict:
    """Extract only the fields the LLM needs — keeps the prompt small."""
    risk = _safe_get(result, "threat_intel", "risk", default={})
    patterns = _safe_get(result, "threat_intel", "patterns", default={})
    dns = _safe_get(result, "threat_intel", "dns", default={})
    abuse = _safe_get(result, "threat_intel", "abuse", default={})
    breakdown = risk.get("breakdown", {})

    # Annotate each scored signal with its evidentiary strength.
    def _classify_strength(signal: str, item: Any) -> str:
        if signal in _SIGNAL_STRENGTH:
            return _SIGNAL_STRENGTH[signal]
        # URL indicators come through as indicator_0, indicator_1, etc.
        if signal.startswith("indicator_"):
            pts = item[0] if isinstance(item, (list, tuple)) and len(item) > 0 else 0
            if pts >= 25:
                return "strong"
            if pts >= 10:
                return "moderate"
            return "weak"
        return "moderate"

    signal_strength = {
        signal: {
            "points": item[0] if isinstance(item, (list, tuple)) and len(item) > 0 else 0,
            "reason": item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else "",
            "strength": _classify_strength(signal, item),
        }
        for signal, item in breakdown.items()
    }

    return {
        "source": source,
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "risk_breakdown": breakdown,
        "signal_strength": signal_strength,
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
            a for a in (_safe_get(result, "header_analysis", "anomalies") or [])[:5]
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
        indicators = result.get("indicators") or []
        # Build a richer breakdown from URL indicators while preserving
        # the raw indicator list for the LLM.
        breakdown = {
            f"indicator_{i}": [ind.get("points", 0), ind.get("flag", "")]
            for i, ind in enumerate(indicators)
        }

        # Derive a few boolean flags that help the LLM reason about the URL.
        is_https = str(result.get("url", "")).lower().startswith("https://")
        hostname = result.get("domain", "")

        return {
            "threat_intel": {
                "risk": {
                    "score": result.get("risk_score", 0),
                    "level": result.get("threat_level", "Low"),
                    "breakdown": breakdown,
                },
                "patterns": {},
                "dns": {},
                "abuse": {},
            },
            "auth": {},
            "spoofing": {},
            "domain_rep": result.get("domain_info", {}),
            "urls": [{
                "url": result.get("url", ""),
                "domain": hostname,
                "mismatch": False,
                "uses_https": is_https,
            }],
            "attachments": [],
            # Extra URL-specific context not present in email results.
            "url_context": {
                "top_indicators": [
                    {"severity": ind.get("severity"), "flag": ind.get("flag"), "points": ind.get("points")}
                    for ind in indicators[:5]
                ],
                "uses_https": is_https,
                "recommendation": result.get("recommendation"),
            },
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


# ── Hallucination guard ───────────────────────────────────────────

def _extract_verified_entities(trimmed: dict) -> set[str]:
    """Collect concrete tokens from the trimmed input that the LLM is
    allowed to reference. Used to catch fabricated domains / senders.

    We intentionally exclude common short words so that a fabricated
    sentence like "Claims to be from MegaBank" is not validated by the
    word "from".
    """
    entities: set[str] = set()

    def add_text(text: Any) -> None:
        if not isinstance(text, str):
            return
        lower = text.lower()
        # Domains (must contain a dot and TLD-like suffix).
        for domain in re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}\b", lower):
            entities.add(domain)
        # Email addresses.
        for email in re.findall(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", lower):
            entities.add(email)
        # Meaningful alphanumeric tokens: either long (>5) or containing
        # a digit / brand-like shape, so we keep "instagram" and "paypa1"
        # but drop "from", "the", "sender".
        for token in re.findall(r"[a-zA-Z0-9._\-@]{3,}", lower):
            if len(token) > 5 or re.search(r"\d", token) or "." in token or "@" in token:
                entities.add(token)

    # Risk breakdown reasons
    for item in trimmed.get("risk_breakdown", {}).values():
        if isinstance(item, (list, tuple)) and len(item) > 1:
            add_text(item[1])

    # Auth / spoofing
    for key in ("spf", "dkim", "dmarc", "compauth", "compauth_reason"):
        add_text(_safe_get(trimmed, "auth", key))
    add_text(_safe_get(trimmed, "spoofing", "from_display"))
    add_text(_safe_get(trimmed, "spoofing", "from_address"))
    for f in _safe_get(trimmed, "spoofing", "findings") or []:
        add_text(f.get("message"))

    # Patterns (urgency / credential / impersonation matched phrases)
    for key in ("urgency", "credential", "impersonation"):
        for phrase in trimmed.get("patterns", {}).get(key) or []:
            entities.add(phrase.lower())

    # URLs
    for u in trimmed.get("urls") or []:
        add_text(u.get("url"))
        add_text(u.get("domain"))

    # Header anomalies
    for a in trimmed.get("header_anomalies") or []:
        add_text(a)

    # Attachments
    for a in trimmed.get("attachments") or []:
        add_text(a.get("filename"))

    # Domain / URL domain reps
    for key in ("domain", "registrar"):
        add_text(_safe_get(trimmed, "domain_rep", key))
    for r in trimmed.get("url_domain_reps") or []:
        add_text(r.get("domain"))

    # URL-specific context
    for ind in _safe_get(trimmed, "url_context", "top_indicators") or []:
        add_text(ind.get("flag"))

    return entities


def _has_verified_reference(text: str, entities: set[str]) -> bool:
    """Return True if ``text`` references at least one verified entity."""
    text_lower = text.lower()
    # Direct substring check supports multi-word matched phrases.
    return any(entity in text_lower for entity in entities)


def _guard_explanation(explanation: dict, trimmed: dict) -> dict:
    """Sanitize an LLM explanation by replacing fabricated specifics.

    - key_concerns without any verified reference are replaced with the
      strongest available verified signal.
    - plain_summary is checked for obviously invented domains; if found,
      it is rewritten using the deterministic fallback.
    """
    entities = _extract_verified_entities(trimmed)
    level = trimmed.get("risk_level", "Unknown")
    score = trimmed.get("risk_score", 0)

    # Build a list of verified concern strings from the strongest signals.
    verified_concerns: list[str] = []
    for signal, meta in sorted(
        trimmed.get("signal_strength", {}).items(),
        key=lambda kv: ({"conclusive": 0, "strong": 1, "moderate": 2, "weak": 3}.get(kv[1].get("strength"), 2), -kv[1].get("points", 0)),
    ):
        reason = meta.get("reason")
        if reason:
            verified_concerns.append(reason)

    # Sanitize key_concerns.
    clean_concerns: list[str] = []
    for concern in explanation.get("key_concerns", []):
        if _has_verified_reference(concern, entities):
            clean_concerns.append(concern)
        elif verified_concerns:
            # Replace with the next strongest verified concern not yet used.
            replacement = verified_concerns.pop(0)
            if replacement not in clean_concerns:
                clean_concerns.append(replacement)
        else:
            clean_concerns.append(concern)
    explanation["key_concerns"] = clean_concerns[:5]

    # Sanitize plain_summary: if it contains a domain-like token not in
    # verified entities, fall back to the deterministic summary.
    summary = explanation.get("plain_summary", "")
    invented_domain = False
    for candidate in re.findall(r"[a-zA-Z0-9\-]{2,}\.[a-zA-Z]{2,}", summary):
        if candidate.lower() not in entities:
            invented_domain = True
            break

    if invented_domain and verified_concerns:
        fallback = _build_fallback({
            "threat_intel": {
                "risk": {
                    "level": level,
                    "score": score,
                    "breakdown": trimmed.get("risk_breakdown", {}),
                }
            }
        })
        explanation["plain_summary"] = fallback["plain_summary"]

    return explanation


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

def _build_user_prompt(trimmed: dict) -> str:
    """Assemble the user prompt with findings, tone, schema, and examples."""
    level = trimmed.get("risk_level", "Unknown")
    tone = _RISK_TONE.get(level, _RISK_TONE["Low"])
    return (
        "Here are the pre-computed security findings:\n"
        + json.dumps(trimmed, indent=2, default=str)
        + "\n\n"
        + tone
        + "\n\n"
        + _OUTPUT_SCHEMA_INSTRUCTION
        + "\n\n"
        + _ONE_SHOT_EXAMPLES
    )


def generate_explanation(
    analysis_result: dict,
    *,
    source: str = "email",
    groq_api_key: str | None = None,
    gemini_api_key: str | None = None,
) -> dict:
    """Produce a human-readable explanation of pre-computed forensic findings.

    Provider chain:  Groq  →  Gemini  →  deterministic fallback.
    Results are cached in-process by a SHA-256 hash of the trimmed input.
    """
    trimmed = _build_trimmed_input(analysis_result, source=source)
    cache_key = hashlib.sha256(
        json.dumps(trimmed, sort_keys=True, default=str).encode()
    ).hexdigest()

    if cache_key in _cache:
        return _cache[cache_key]

    user_prompt = _build_user_prompt(trimmed)

    # ── Try Groq ────────────────────────────────────────────────
    if groq_api_key:
        try:
            raw = _call_groq(user_prompt, groq_api_key)
            explanation = _parse_llm_response(raw)
            explanation["provider"] = "groq"
            explanation = _guard_explanation(explanation, trimmed)
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
            explanation = _guard_explanation(explanation, trimmed)
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
    source: str = "email",
    groq_api_key: str | None = None,
    gemini_api_key: str | None = None,
) -> dict:
    """Async version of generate_explanation.

    The blocking Groq/Gemini SDK calls are offloaded to threads via
    asyncio.to_thread so the event loop is never blocked.
    """
    trimmed = _build_trimmed_input(analysis_result, source=source)
    cache_key = hashlib.sha256(
        json.dumps(trimmed, sort_keys=True, default=str).encode()
    ).hexdigest()

    if cache_key in _cache:
        return _cache[cache_key]

    user_prompt = _build_user_prompt(trimmed)

    # ── Try Groq (blocking SDK → thread) ───────────────────────
    if groq_api_key:
        try:
            raw = await asyncio.to_thread(_call_groq, user_prompt, groq_api_key)
            explanation = _parse_llm_response(raw)
            explanation["provider"] = "groq"
            explanation = _guard_explanation(explanation, trimmed)
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
            explanation = _guard_explanation(explanation, trimmed)
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
