"""Abstract upstream LLM provider interface."""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Protocol

import httpx

UPSTREAM_TIMEOUT = 60.0


class Provider(Protocol):
    async def chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Forward `payload` (OpenAI-shaped chat completion request) upstream
        and return the provider's response as a plain dict."""
        ...


class UpstreamProviderError(Exception):
    """Raised when the upstream provider call fails (network error, non-2xx,
    a body that isn't the JSON the adapter expects, etc.)."""


class UpstreamClient:
    """One long-lived `httpx.AsyncClient` per provider (LIMITATIONS.md L2-2).

    Building an AsyncClient loads the CA bundle synchronously (~300 ms that
    blocks the event loop), and a fresh client also throws away the pooled
    keep-alive connection. So the app lifespan calls `open()` once at startup
    and `aclose()` at shutdown, and every upstream call reuses the client.
    Outside the lifespan (tests, scripts) `client()` falls back to a
    short-lived client per call, the module 2 behaviour.
    """

    def __init__(self, base_url: str):
        self._base_url = base_url
        self._client: httpx.AsyncClient | None = None

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self._base_url, timeout=UPSTREAM_TIMEOUT)

    @property
    def is_open(self) -> bool:
        return self._client is not None

    def open(self) -> None:
        if self._client is None:
            self._client = self._new_client()

    async def aclose(self) -> None:
        if self._client is not None:
            client, self._client = self._client, None
            await client.aclose()

    @asynccontextmanager
    async def client(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
            return
        async with self._new_client() as client:
            yield client
