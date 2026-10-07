"""Output-side leakage checks, used by `app/core/stages/output_scan.py`. See
project_plan/05-threat-detection-classifier.md §4.

Two independent, purely text-based checks against the provider's response:

  1. System-prompt echo - does the response contain the request's system
     prompt verbatim (ignoring incidental whitespace differences)?
  2. Redaction-token echo - does the response contain a `[REDACTED_<TYPE>]`
     placeholder (module 4's mask-mode token), which would mean the model
     echoed back a token it was never supposed to treat as live content?

Both checks only ever look at text already present in the request/response
- never RedactionVault - so this module structurally cannot reintroduce
raw PII, independent of whatever module 4 does.
"""
import re
from typing import Any

REDACTION_TOKEN_RE = re.compile(r"\[REDACTED_[A-Z_]+\]")

# A verbatim-substring match against a very short system prompt (e.g. "Be
# concise.") would false-positive on ordinary responses that happen to
# contain the same common phrase. Below this length, skip the check rather
# than report a meaningless match.
MIN_SYSTEM_PROMPT_LENGTH_FOR_ECHO_CHECK = 20


def _normalize(text: str) -> str:
    return " ".join(text.split())


def extract_system_prompt(body: dict[str, Any]) -> str:
    for message in body.get("messages", []):
        if message.get("role") == "system" and isinstance(message.get("content"), str):
            return message["content"]
    return ""


def extract_response_text(response_body: dict[str, Any]) -> str:
    parts = []
    for choice in response_body.get("choices", []):
        content = choice.get("message", {}).get("content")
        if isinstance(content, str):
            parts.append(content)
    return "\n".join(parts)


def detect_system_prompt_echo(system_prompt: str, response_text: str) -> bool:
    if not system_prompt or not response_text:
        return False
    normalized_system = _normalize(system_prompt)
    if len(normalized_system) < MIN_SYSTEM_PROMPT_LENGTH_FOR_ECHO_CHECK:
        return False
    return normalized_system in _normalize(response_text)


def detect_redaction_token_echo(response_text: str) -> list[str]:
    if not response_text:
        return []
    return REDACTION_TOKEN_RE.findall(response_text)
