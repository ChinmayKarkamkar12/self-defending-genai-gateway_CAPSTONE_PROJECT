"""Maps a `model` string prefix to the right provider adapter."""
from app.core.providers.anthropic import AnthropicProvider
from app.core.providers.base import Provider
from app.core.providers.openai import OpenAIProvider

_OPENAI = OpenAIProvider()
_ANTHROPIC = AnthropicProvider()

_PREFIX_MAP: dict[str, Provider] = {
    "gpt-": _OPENAI,
    "claude-": _ANTHROPIC,
}


class UnknownModelError(Exception):
    pass


def get_provider(model: str) -> Provider:
    for prefix, provider in _PREFIX_MAP.items():
        if model.startswith(prefix):
            return provider
    raise UnknownModelError(f"no provider registered for model '{model}'")
