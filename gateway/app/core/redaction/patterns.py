"""Custom regex detection layer, run after Presidio and merged with its
results (see merge.py). Covers formats Presidio's built-in recognizers
handle poorly or don't cover at all: this project's demo API key formats and
Luhn-validated credit card numbers. See project_plan/04-pii-redaction.md §3.
"""
import re

from app.core.redaction.spans import SOURCE_REGEX, Span

# Regex matches aren't probabilistic - a pattern either matches or it
# doesn't, so there's no real "confidence" to report. This score exists only
# because `Span.score` is a shared field; it must never be compared directly
# against Presidio's genuine NLP confidence (see merge.py's resolution
# rule - regex wins outright on its own entity types via `source`, not via
# this number).
_REGEX_MATCH_SCORE = 1.0

# OpenAI-style secret keys (`sk-...`) and AWS access key IDs (`AKIA...`) -
# the two API key shapes most likely to show up pasted into a prompt by
# accident.
_API_KEY_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]

# Candidate credit-card-shaped digit runs (13-19 digits, optionally grouped
# with spaces or dashes) - narrowed down to real matches via Luhn validation
# below, since plenty of 16-digit numbers aren't card numbers.
_CARD_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_api_keys(text: str) -> list[Span]:
    spans = []
    for pattern in _API_KEY_PATTERNS:
        for match in pattern.finditer(text):
            spans.append(
                Span(
                    match.start(), match.end(), "API_KEY", _REGEX_MATCH_SCORE, SOURCE_REGEX
                )
            )
    return spans


def detect_credit_cards(text: str) -> list[Span]:
    spans = []
    for match in _CARD_CANDIDATE_PATTERN.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            spans.append(
                Span(
                    match.start(),
                    match.end(),
                    "CREDIT_CARD",
                    _REGEX_MATCH_SCORE,
                    SOURCE_REGEX,
                )
            )
    return spans


def detect_custom(text: str) -> list[Span]:
    """Run every custom regex recognizer and return the combined spans,
    unmerged - callers pass this through merge.merge_spans alongside
    Presidio's results.
    """
    return detect_api_keys(text) + detect_credit_cards(text)
