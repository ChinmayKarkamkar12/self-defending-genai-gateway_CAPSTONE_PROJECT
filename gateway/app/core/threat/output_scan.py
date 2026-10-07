"""Output-side leakage checks, used by `app/core/stages/output_scan.py`. See
project_plan/05-threat-detection-classifier.md §4.

Two independent, purely text-based checks against the provider's response:

  1. System-prompt leak - does the response reproduce the request's system
     prompt, in full or as a long verbatim run of its words? Comparison is
     on lowercased word sequences, so case, punctuation, and whitespace
     changes don't hide a leak.
  2. Redaction-token echo - does the response contain a module 4
     placeholder, either mask mode's `[REDACTED_<TYPE>]` or tokenize mode's
     `[REDACTED_<TYPE>_<8 hex>]`?

Both checks only ever look at text already present in the request/response
- never RedactionVault - so this module structurally cannot reintroduce
raw PII, independent of whatever module 4 does.

KNOWN LIMITATION: the system-prompt check only catches verbatim word runs.
A model that paraphrases, translates, summarises, or encodes (e.g. base64)
its instructions before revealing them is not detected - that would need
semantic similarity or a second model. See training/README.md "Known
limitations".
"""
import re
from typing import Any

from app.core.messages import content_text_parts, message_text

REDACTION_TOKEN_RE = re.compile(r"\[REDACTED_[A-Z_]+?(?:_[0-9a-f]{8})?\]")

# A match against a very short system prompt (e.g. "Be concise.") would
# false-positive on ordinary responses that happen to contain the same
# common phrase. Below this length, skip the check rather than report a
# meaningless match.
MIN_SYSTEM_PROMPT_LENGTH_FOR_ECHO_CHECK = 20

# A run of this many consecutive system-prompt words appearing verbatim in
# the response counts as a (partial) leak. 12 words is long enough that it
# doesn't happen by coincidence - common boilerplate like "You are a helpful
# assistant" is 5 - but short enough to catch a model that leaks one
# sentence of its instructions rather than all of them.
PARTIAL_LEAK_MIN_WORDS = 12


def _words(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def _ngrams(words: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def extract_system_prompt(body: dict[str, Any]) -> str:
    parts = [
        message_text(m)
        for m in body.get("messages", [])
        if isinstance(m, dict) and m.get("role") in ("system", "developer")
    ]
    return "\n".join(p for p in parts if p)


def extract_response_text(response_body: dict[str, Any]) -> str:
    parts: list[str] = []
    for choice in response_body.get("choices", []):
        parts.extend(content_text_parts(choice.get("message", {}).get("content")))
    return "\n".join(parts)


def detect_system_prompt_echo(system_prompt: str, response_text: str) -> bool:
    if not system_prompt or not response_text:
        return False
    if len(" ".join(system_prompt.split())) < MIN_SYSTEM_PROMPT_LENGTH_FOR_ECHO_CHECK:
        return False
    prompt_words, response_words = _words(system_prompt), _words(response_text)
    n = min(PARTIAL_LEAK_MIN_WORDS, len(prompt_words))
    if n == 0 or len(response_words) < n:
        return False
    return not _ngrams(prompt_words, n).isdisjoint(_ngrams(response_words, n))


def detect_redaction_token_echo(response_text: str) -> list[str]:
    if not response_text:
        return []
    return REDACTION_TOKEN_RE.findall(response_text)
