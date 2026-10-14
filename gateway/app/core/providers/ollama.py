"""Optional local Ollama provider adapter.

Off unless OLLAMA_BASE_URL is set (see app/config.py). Ollama serves an
OpenAI-compatible `/chat/completions`, so no payload translation is needed:
the gateway-side model name `local-<name>` is forwarded as `<name>`. It's a
separate prefix rather than a stand-in for `gpt-*` so the audit log and
usage records name the model that really answered, and its cost is 0.
"""
from typing import Any

import httpx

from app.config import settings
from app.core.providers.base import UpstreamClient, UpstreamProviderError, describe_http_error

LOCAL_MODEL_PREFIX = "local-"


def ollama_enabled() -> bool:
    return bool(settings.OLLAMA_BASE_URL)


class OllamaProvider:
    def __init__(self) -> None:
        # Read when a client is built, so the setting can't go stale.
        self.http = UpstreamClient(lambda: settings.OLLAMA_BASE_URL)

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not ollama_enabled():
            raise UpstreamProviderError("local provider is not configured")
        upstream_payload = {
            **payload,
            "model": payload["model"].removeprefix(LOCAL_MODEL_PREFIX),
        }
        try:
            async with self.http.client() as client:
                response = await client.post("/chat/completions", json=upstream_payload)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise UpstreamProviderError(describe_http_error(exc)) from exc
        except ValueError as exc:
            raise UpstreamProviderError("response body is not valid JSON") from exc
