"""NLP-based phishing text classifier using zero-shot classification.

Provides a lightweight offline ML layer that catches subtle manipulation
techniques (emotional pressure, false authority, social engineering) that
bypass static regex pattern lists.

Uses HuggingFace ``transformers`` zero-shot classification pipeline backed
by a DeBERTa-v3 NLI model fine-tuned on MNLI + FEVER + ANLI.  The model
is lazy-loaded on first use so application startup is not affected.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────
_MODEL_NAME = "MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli"

# Labels aligned with the regex categories plus a general manipulation
# label for subtle social-engineering patterns regex can't catch.
_LABELS: list[str] = [
    "urgency",
    "credential theft",
    "brand impersonation",
    "social manipulation",
]

# Minimum confidence score for a label to be considered a positive
# detection.  Below this threshold the signal is treated as noise.
# Set to 0.70 to reduce false positives on legitimate business emails
# while preserving sensitivity to genuine phishing language.
_CONFIDENCE_THRESHOLD = 0.70

# ── Lazy-loaded singleton ─────────────────────────────────────────
_classifier: Any | None = None
_load_attempted: bool = False


def _get_classifier() -> Any | None:
    """Lazily load the zero-shot classification pipeline.

    Returns ``None`` if the model cannot be loaded (missing dependency,
    no internet for first download, etc.) so callers can gracefully
    degrade to regex-only detection.
    """
    global _classifier, _load_attempted
    if _load_attempted:
        return _classifier
    _load_attempted = True
    try:
        from transformers import pipeline  # lazy import

        _classifier = pipeline(
            "zero-shot-classification",
            model=_MODEL_NAME,
            device=-1,  # CPU — keeps GPU optional
        )
        log.info("NLP phishing classifier loaded (model=%s)", _MODEL_NAME)
    except Exception as exc:
        log.warning(
            "NLP phishing classifier unavailable (%s). "
            "Falling back to regex-only detection.",
            exc,
        )
        _classifier = None
    return _classifier


def classify_text(text: str) -> dict:
    """Classify email/URL text for phishing indicators using the NLP model.

    Returns a dict with:
        - ``scores``    : ``{label: confidence}`` for every label
        - ``flagged``   : ``[label, ...]`` where confidence >= threshold
        - ``ml_max_score``: highest confidence across all labels (float)
        - ``available`` : whether the ML model was loaded

    If the model is unavailable, returns an empty result with
    ``available=False``.
    """
    classifier = _get_classifier()
    if classifier is None or not text or not text.strip():
        return {
            "scores": {},
            "flagged": [],
            "ml_max_score": 0.0,
            "available": classifier is not None,
        }

    # Truncate very long texts — the model has a 512-token window and
    # phishing signals are concentrated in the first ~1500 chars.
    truncated = text[:1500]

    try:
        result = classifier(
            truncated,
            candidate_labels=_LABELS,
            multi_label=True,
        )

        scores: dict[str, float] = {
            label: round(score, 4)
            for label, score in zip(result["labels"], result["scores"])
        }
        flagged = [
            label for label, score in scores.items()
            if score >= _CONFIDENCE_THRESHOLD
        ]
        ml_max_score = max(scores.values()) if scores else 0.0

        return {
            "scores": scores,
            "flagged": flagged,
            "ml_max_score": ml_max_score,
            "available": True,
        }
    except Exception as exc:
        log.warning("NLP classification failed: %s", exc)
        return {
            "scores": {},
            "flagged": [],
            "ml_max_score": 0.0,
            "available": True,
        }
