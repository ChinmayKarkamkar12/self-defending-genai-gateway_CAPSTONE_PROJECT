"""Anthropic provider adapter.

Anthropic's native API is not OpenAI-shaped, but this module accepts the
OpenAI-shaped payload the gateway standardizes on and adapts it, so callers
of `chat_completion` never see the difference between providers.
"""
from typing import Any

import httpx

from app.config import settings
from app.core.providers.base import UpstreamProviderError

ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1"
ANTHROPIC_VERSION = "2023-06-01"


def _to_anthropic_payload(payload: dict[str, Any]) -> dict[str, Any]:
    messages = [m for m in payload.get("messages", []) if m.get("role") != "system"]
    system = next(
        (m["content"] for m in payload.get("messages", []) if m.get("role") == "system"), None
    )
    anthropic_payload: dict[str, Any] = {
        "model": payload["model"],
        "messages": messages,
        "max_tokens": payload.get("max_tokens", 1024),
    }
    if system is not None:
        anthropic_payload["system"] = system
    return anthropic_payload


def _to_openai_response(payload: dict[str, Any]) -> dict[str, Any]:
    text = "".join(block.get("text", "") for block in payload.get("content", []))
    return {
        "id": payload.get("id"),
        "object": "chat.completion",
        "model": payload.get("model"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": payload.get("stop_reason"),
            }
        ],
        "usage": {
            "prompt_tokens": payload.get("usage", {}).get("input_tokens"),
            "completion_tokens": payload.get("usage", {}).get("output_tokens"),
        },
    }


class AnthropicProvider:
    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(base_url=ANTHROPIC_BASE_URL, timeout=60.0) as client:
                response = await client.post(
                    "/messages",
                    json=_to_anthropic_payload(payload),
                    headers={
                        "x-api-key": settings.ANTHROPIC_API_KEY,
                        "anthropic-version": ANTHROPIC_VERSION,
                    },
                )
                response.raise_for_status()
                return _to_openai_response(response.json())
        except httpx.HTTPError as exc:
            raise UpstreamProviderError(str(exc)) from exc
