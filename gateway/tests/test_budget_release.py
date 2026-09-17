"""Integration tests for the budget reservation release path.

budget_check_stage reserves an estimated cost atomically (see
test_budget_stage.py's concurrency test for why). If the request never
reaches usage_recording_stage to reconcile that estimate to the real cost -
blocked downstream, unknown model, upstream failure - the reservation must
be refunded by the chat endpoint, or the team's spend counter would
permanently overstate what was actually spent.
"""
from datetime import UTC, datetime
from decimal import Decimal

import respx
from httpx import Response

from app.core.providers.openai import OPENAI_BASE_URL
from app.db.models import BudgetPeriod, BudgetPolicy
from tests.conftest import RAW_TEST_KEY


def _today_key() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


async def _add_policy(db_session, team, *, limit_usd="10.00", rate_limit_rps=100):
    db_session.add(
        BudgetPolicy(
            team_id=team.id,
            period=BudgetPeriod.DAILY,
            limit_usd=Decimal(limit_usd),
            rate_limit_rps=rate_limit_rps,
        )
    )
    await db_session.commit()


async def test_reservation_refunded_on_unknown_model(
    client, db_session, fake_redis, seeded_team_and_key
):
    team, _ = seeded_team_and_key
    await _add_policy(db_session, team)

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "not-a-real-model", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 422
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert spend is None or Decimal(spend) == Decimal("0")


@respx.mock
async def test_reservation_refunded_on_upstream_error(
    client, db_session, fake_redis, seeded_team_and_key
):
    team, _ = seeded_team_and_key
    await _add_policy(db_session, team)
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(return_value=Response(500))

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 502
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert spend is None or Decimal(spend) == Decimal("0")


@respx.mock
async def test_successful_request_reconciles_to_actual_cost(
    client, db_session, fake_redis, seeded_team_and_key
):
    team, _ = seeded_team_and_key
    await _add_policy(db_session, team)
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(
            200,
            json={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "model": "gpt-4o",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hi"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )
    )

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 200
    # gpt-4o: 10/1e6*2.50 + 5/1e6*10.00 = 0.000075, not the pre-call
    # reservation (sized off max_tokens/default estimate).
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert Decimal(spend) == Decimal("0.000075")
