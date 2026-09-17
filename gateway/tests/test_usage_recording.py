from decimal import Decimal

import respx
from httpx import Response
from sqlalchemy import select

from app.core.providers.openai import OPENAI_BASE_URL
from app.db.models import UsageRecord
from tests.conftest import RAW_TEST_KEY


@respx.mock
async def test_post_call_writes_usage_record(client, db_session, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "model": "gpt-4o",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hi there"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 500},
            },
        )
    )

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 200

    result = await db_session.execute(
        select(UsageRecord).where(UsageRecord.team_id == team.id)
    )
    record = result.scalar_one()

    assert record.api_key_id == api_key.id
    assert record.model == "gpt-4o"
    assert record.tokens_in == 1000
    assert record.tokens_out == 500
    # gpt-4o: 1000/1e6 * 2.50 + 500/1e6 * 10.00
    assert record.cost_usd == Decimal("0.007500")
