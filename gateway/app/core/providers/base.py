"""Abstract upstream LLM provider interface."""
from typing import Any, Protocol


class Provider(Protocol):
    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Forward `payload` (OpenAI-shaped chat completion request) upstream
        and return the provider's response as a plain dict."""
        ...


class UpstreamProviderError(Exception):
    """Raised when the upstream provider call fails (network error, non-2xx, etc.)."""
