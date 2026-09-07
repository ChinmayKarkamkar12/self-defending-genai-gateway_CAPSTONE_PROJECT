import respx
from httpx import Response

from app.core.providers.openai import OPENAI_BASE_URL
from tests.conftest import RAW_TEST_KEY


@respx.mock
async def test_end_to_end_with_mocked_provider(client):
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "model": "gpt-4",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hi there"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            },
        )
    )

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "hi there"
    assert "x-gateway-request-id" in response.headers


async def test_missing_auth_header_rejected(client):
    response = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 401


async def test_invalid_api_key_rejected(client):
    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer sk-gw-wrong-key"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 401


@respx.mock
async def test_upstream_error_returns_502(client):
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(return_value=Response(500))

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 502
