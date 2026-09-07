import pytest

from app.core.providers.anthropic import AnthropicProvider
from app.core.providers.openai import OpenAIProvider
from app.core.providers.registry import UnknownModelError, get_provider


def test_registry_routes_by_model_prefix():
    assert isinstance(get_provider("gpt-4"), OpenAIProvider)
    assert isinstance(get_provider("gpt-4o-mini"), OpenAIProvider)
    assert isinstance(get_provider("claude-3-5-sonnet-20241022"), AnthropicProvider)


def test_registry_raises_for_unknown_model():
    with pytest.raises(UnknownModelError):
        get_provider("llama-3-70b")
