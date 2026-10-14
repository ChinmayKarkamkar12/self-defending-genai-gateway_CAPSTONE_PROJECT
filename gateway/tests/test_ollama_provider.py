"""The optional local Ollama provider: off by default, and when switched on,
a `local-*` model goes through the full pipeline like any other."""
import json
from decimal import Decimal

import pytest
import respx
from httpx import Response

from app.config import settings
from app.core.audit.entry import UNRECOGNIZED_MODEL, safe_model_name
from app.core.governance.pricing import calculate_cost
from app.core.providers.base import UpstreamProviderError
from app.core.providers.ollama import OllamaProvider
from app.core.providers.registry import UnknownModelError, get_provider
from app.db.models import AuditOutcome
from tests.audit_helpers import AUTH, all_entries, chat_body

OLLAMA_URL = "http://ollama.test:11434/v1"
_OLLAMA_OK = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "llama3:latest",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "Paris."}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 20, "completion_tokens": 3, "total_tokens": 23},
}


@pytest.fixture
def ollama_on(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_BASE_URL", OLLAMA_URL)


@pytest.fixture
def ollama_off(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_BASE_URL", "")


def test_local_models_are_unknown_when_not_configured(ollama_off):
    with pytest.raises(UnknownModelError):
        get_provider("local-llama3")
    assert safe_model_name("local-llama3") == UNRECOGNIZED_MODEL


def test_local_models_route_to_ollama_when_configured(ollama_on):
    assert isinstance(get_provider("local-llama3"), OllamaProvider)
    assert safe_model_name("local-llama3:latest") == "local-llama3:latest"


def test_existing_providers_unaffected_by_the_option(ollama_on):
    assert not isinstance(get_provider("gpt-4o"), OllamaProvider)
    assert not isinstance(get_provider("claude-3-haiku-20240307"), OllamaProvider)


def test_local_models_cost_nothing():
    assert calculate_cost("local-llama3", 1_000_000, 1_000_000) == Decimal("0")


@respx.mock
async def test_forwards_bare_model_name_without_provider_keys(ollama_on):
    route = respx.post(f"{OLLAMA_URL}/chat/completions").mock(
        return_value=Response(200, json=_OLLAMA_OK)
    )

    result = await OllamaProvider().chat_completion(chat_body(model="local-llama3"))

    assert result == _OLLAMA_OK
    sent = route.calls.last.request
    assert json.loads(sent.content)["model"] == "llama3"
    # Upstream provider keys are never sent to the local server.
    assert "authorization" not in sent.headers
    assert "x-api-key" not in sent.headers


@respx.mock
async def test_end_to_end_request_is_allowed_and_audited(
    ollama_on, client, audit_writer, session_maker
):
    respx.post(f"{OLLAMA_URL}/chat/completions").mock(
        return_value=Response(200, json=_OLLAMA_OK)
    )

    response = await client.post(
        "/v1/chat/completions",
        headers=AUTH,
        json=chat_body("What is the capital of France?", model="local-llama3"),
    )
    await audit_writer.flush()

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Paris."
    (entry,) = await all_entries(session_maker)
    assert entry.outcome == AuditOutcome.ALLOWED
    assert entry.model == "local-llama3"
    assert (entry.tokens_in, entry.tokens_out) == (20, 3)
    assert entry.cost_usd == Decimal("0")


async def test_local_model_rejected_end_to_end_when_off(
    ollama_off, client, audit_writer, session_maker
):
    response = await client.post(
        "/v1/chat/completions", headers=AUTH, json=chat_body(model="local-llama3")
    )
    await audit_writer.flush()

    assert response.status_code == 422
    (entry,) = await all_entries(session_maker)
    assert entry.outcome == AuditOutcome.REJECTED_UNKNOWN_MODEL


async def test_refuses_to_call_when_not_configured(ollama_off):
    with pytest.raises(UpstreamProviderError, match="local provider is not configured"):
        await OllamaProvider().chat_completion(chat_body(model="local-llama3"))


@respx.mock
@pytest.mark.parametrize(
    ("reply", "message"),
    [
        # Ollama answers 404 for a model it hasn't pulled. The client is told
        # the status, not the internal URL httpx would quote (module 9).
        (Response(404, text="model 'llama3' not found"), "provider returned HTTP 404"),
        (Response(200, text="<html>not json</html>"), "response body is not valid JSON"),
    ],
)
async def test_errors_are_upstream_errors_without_the_server_address(ollama_on, reply, message):
    respx.post(f"{OLLAMA_URL}/chat/completions").mock(return_value=reply)

    with pytest.raises(UpstreamProviderError) as caught:
        await OllamaProvider().chat_completion(chat_body(model="local-llama3"))

    assert str(caught.value) == message
    assert "ollama.test" not in str(caught.value)


def test_demo_price_makes_local_models_cost_something(monkeypatch):
    # Module 10: a pretend price so a budget can run out in a live demo.
    monkeypatch.setattr(settings, "LOCAL_MODEL_DEMO_PRICE_PER_MILLION", Decimal("40"))

    assert calculate_cost("local-llama3", 100, 200) == Decimal("0.012000")
    # Real providers keep their real prices.
    assert calculate_cost("gpt-4", 1_000_000, 0) == Decimal("30.000000")
