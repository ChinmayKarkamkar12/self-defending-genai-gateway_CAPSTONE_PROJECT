"""OpenAI provider adapter."""
from typing import Any

import httpx

from app.config import settings
from app.core.providers.base import UpstreamProviderError

OPENAI_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider:
    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(base_url=OPENAI_BASE_URL, timeout=60.0) as client:
                response = await client.post(
                    "/chat/completions",
                    json=payload,
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise UpstreamProviderError(str(exc)) from exc
