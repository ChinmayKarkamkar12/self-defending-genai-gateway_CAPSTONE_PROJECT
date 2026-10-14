"""OpenAI provider adapter."""
from typing import Any

import httpx

from app.config import settings
from app.core.providers.base import UpstreamClient, UpstreamProviderError, describe_http_error

OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider:
    def __init__(self) -> None:
        self.http = UpstreamClient(OPENAI_BASE_URL)

    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with self.http.client() as client:
                response = await client.post(
                    "/chat/completions",
                    json=payload,
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise UpstreamProviderError(describe_http_error(exc)) from exc
        except ValueError as exc:
            # A 2xx whose body isn't JSON (e.g. a proxy's HTML error page).
            raise UpstreamProviderError("response body is not valid JSON") from exc
