"""Abstract upstream LLM provider interface."""
from collections.abc import AsyncIterator, Callable
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
    a body that isn't the JSON the adapter expects, etc.).

    Its message goes back to the client (chat.py's 502 detail), so it is
    always one of the gateway's own descriptions - see `describe_http_error`."""


def describe_http_error(exc: httpx.HTTPError) -> str:
    """What the client is told about a failed upstream call: the status code
    or the kind of failure, never the exception's own text. That text is
    written by httpx or a network library and can carry the upstream URL (an
    internal Ollama host, say) or whatever an error path chose to quote - a
    provider key included. Module 9's security boundary tests found the
    raw text reaching clients."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"provider returned HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "provider timed out"
    return f"provider unreachable ({type(exc).__name__})"


class UpstreamClient:
    """One long-lived `httpx.AsyncClient` per provider (LIMITATIONS.md L2-2).

    Building an AsyncClient loads the CA bundle synchronously (~300 ms that
    blocks the event loop), and a fresh client also throws away the pooled
    keep-alive connection. So the app lifespan calls `open()` once at startup
    and `aclose()` at shutdown, and every upstream call reuses the client.
    Outside the lifespan (tests, scripts) `client()` falls back to a
    short-lived client per call, the module 2 behaviour.
    """

    def __init__(self, base_url: str | Callable[[], str]):
        # A callable is read each time a client is built (a configurable URL).
        self._base_url = base_url
        self._client: httpx.AsyncClient | None = None

    def _new_client(self) -> httpx.AsyncClient:
        base_url = self._base_url() if callable(self._base_url) else self._base_url
        return httpx.AsyncClient(base_url=base_url, timeout=UPSTREAM_TIMEOUT)

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
