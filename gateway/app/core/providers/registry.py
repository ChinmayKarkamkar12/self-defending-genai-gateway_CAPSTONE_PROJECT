"""Maps a `model` string prefix to the right provider adapter."""
from app.core.providers.anthropic import AnthropicProvider
from app.core.providers.base import Provider
from app.core.providers.ollama import LOCAL_MODEL_PREFIX, OllamaProvider, ollama_enabled
from app.core.providers.openai import OpenAIProvider

_OPENAI = OpenAIProvider()
_ANTHROPIC = AnthropicProvider()
# Optional, only routed to when OLLAMA_BASE_URL is set (see get_provider).
_OLLAMA = OllamaProvider()

_PREFIX_MAP: dict[str, Provider] = {
    "gpt-": _OPENAI,
    "claude-": _ANTHROPIC,
}


class UnknownModelError(Exception):
    pass


def get_provider(model: str) -> Provider:
    if model.startswith(LOCAL_MODEL_PREFIX) and ollama_enabled():
        return _OLLAMA
    for prefix, provider in _PREFIX_MAP.items():
        if model.startswith(prefix):
            return provider
    raise UnknownModelError(f"no provider registered for model '{model}'")


def open_upstream_clients() -> None:
    """Called once from the app lifespan: one pooled client per provider."""
    _OPENAI.http.open()
    _ANTHROPIC.http.open()
    if ollama_enabled():
        _OLLAMA.http.open()


async def close_upstream_clients() -> None:
    await _OPENAI.http.aclose()
    await _ANTHROPIC.http.aclose()
    await _OLLAMA.http.aclose()
