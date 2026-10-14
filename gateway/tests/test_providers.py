import httpx
import pytest
import respx
from httpx import Response

from app.core.providers.anthropic import ANTHROPIC_BASE_URL, AnthropicProvider
from app.core.providers.base import UpstreamProviderError, describe_http_error
from app.core.providers.openai import OPENAI_BASE_URL, OpenAIProvider
from app.core.providers.registry import UnknownModelError, get_provider


def test_registry_routes_by_model_prefix():
    assert isinstance(get_provider("gpt-4"), OpenAIProvider)
    assert isinstance(get_provider("gpt-4o-mini"), OpenAIProvider)
    assert isinstance(get_provider("claude-3-5-sonnet-20241022"), AnthropicProvider)


def test_registry_raises_for_unknown_model():
    with pytest.raises(UnknownModelError):
        get_provider("llama-3-70b")


_OPENAI_OK = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}
_PAYLOAD = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}


@respx.mock
async def test_open_client_is_reused_across_calls(monkeypatch):
    """L2-2: once opened (app lifespan), every call reuses one client
    instead of building a new one (and reloading the CA bundle) per call."""
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(200, json=_OPENAI_OK)
    )
    provider = OpenAIProvider()
    provider.http.open()
    created = []
    real_init = httpx.AsyncClient.__init__

    def counting_init(self, *args, **kwargs):
        created.append(self)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", counting_init)
    try:
        for _ in range(3):
            assert await provider.chat_completion(_PAYLOAD) == _OPENAI_OK
        assert created == []
    finally:
        await provider.http.aclose()
    assert not provider.http.is_open


@respx.mock
async def test_unopened_client_falls_back_to_per_call_client():
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(200, json=_OPENAI_OK)
    )
    provider = OpenAIProvider()
    assert not provider.http.is_open
    assert await provider.chat_completion(_PAYLOAD) == _OPENAI_OK


@respx.mock
async def test_openai_non_json_body_is_an_upstream_error():
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(200, text="<html>oops</html>")
    )
    with pytest.raises(UpstreamProviderError):
        await OpenAIProvider().chat_completion(_PAYLOAD)


@respx.mock
@pytest.mark.parametrize(
    "response",
    [Response(200, text="<html>oops</html>"), Response(200, json={"content": "not a list"})],
)
async def test_anthropic_malformed_body_is_an_upstream_error(response):
    respx.post(f"{ANTHROPIC_BASE_URL}/messages").mock(return_value=response)
    payload = {**_PAYLOAD, "model": "claude-3-5-sonnet-20241022"}
    with pytest.raises(UpstreamProviderError):
        await AnthropicProvider().chat_completion(payload)


@pytest.mark.parametrize(
    ("error", "described"),
    [
        (
            httpx.HTTPStatusError(
                "Client error '404' for url 'http://ollama.internal:11434/v1/chat/completions'",
                request=httpx.Request("POST", "http://ollama.internal:11434/v1/chat/completions"),
                response=httpx.Response(404),
            ),
            "provider returned HTTP 404",
        ),
        (httpx.ReadTimeout("timed out reading from 10.0.0.7"), "provider timed out"),
        (
            httpx.ConnectError("[Errno 111] refused: 10.0.0.7:443"),
            "provider unreachable (ConnectError)",
        ),
    ],
)
def test_upstream_errors_are_described_without_their_own_text(error, described):
    # The client sees this text (the 502 detail): no URL, host or quoted content.
    assert describe_http_error(error) == described


@respx.mock
async def test_upstream_error_detail_hides_the_upstream_url():
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(return_value=Response(503))

    with pytest.raises(UpstreamProviderError) as caught:
        await OpenAIProvider().chat_completion(_PAYLOAD)

    assert str(caught.value) == "provider returned HTTP 503"
    assert "openai.com" not in str(caught.value)
