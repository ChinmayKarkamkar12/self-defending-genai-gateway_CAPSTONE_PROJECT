"""Pre-call token estimation and post-call usage extraction.

Pre-call, we only have the request body, so we estimate input tokens with
tiktoken for OpenAI models (best-effort for Anthropic, which doesn't publish
a public tokenizer — falls back to a whitespace heuristic). Post-call, the
provider's own reported `usage` block is authoritative and always preferred.

See project_plan/03-cost-usage-governance.md §6 task 3.
"""
from typing import Any

import tiktoken

_DEFAULT_ENCODING = "cl100k_base"


def _encoding_for_model(model: str) -> tiktoken.Encoding:
    try:
        return tiktoken.encoding_for_model(model)
    except KeyError:
        return tiktoken.get_encoding(_DEFAULT_ENCODING)


def estimate_input_tokens(model: str, messages: list[dict[str, Any]]) -> int:
    """Best-effort pre-call estimate of input tokens from a chat messages list."""
    encoding = _encoding_for_model(model)
    total = 0
    for message in messages:
        content = message.get("content", "")
        if isinstance(content, str):
            total += len(encoding.encode(content))
    return total


def extract_usage(response: dict[str, Any]) -> tuple[int, int]:
    """Return (tokens_in, tokens_out) from a provider's OpenAI-shaped response.

    This is the authoritative source once a response exists - always prefer it
    over the pre-call estimate.
    """
    usage = response.get("usage") or {}
    tokens_in = usage.get("prompt_tokens") or 0
    tokens_out = usage.get("completion_tokens") or 0
    return int(tokens_in), int(tokens_out)
