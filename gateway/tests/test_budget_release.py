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

from app.core.context import StageResult
from app.core.providers.openai import OPENAI_BASE_URL
from app.core.stages.budget_check import budget_check_stage
from app.db.models import BudgetPeriod, BudgetPolicy
from tests.conftest import RAW_TEST_KEY

_SUCCESSFUL_RESPONSE_JSON = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "gpt-4o",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
}


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
        return_value=Response(200, json=_SUCCESSFUL_RESPONSE_JSON)
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


async def test_reservation_refunded_when_pre_call_stage_raises(
    client, db_session, fake_redis, seeded_team_and_key, monkeypatch
):
    """budget_check_stage reserves successfully, then a later pre-call stage
    (threat_detection/pii_redaction in production; a stand-in here since
    those are still no-op stubs) raises -> StageFailure -> 503. The
    reservation must not be left stranded on the counter.
    """
    team, _ = seeded_team_and_key
    await _add_policy(db_session, team)

    async def _raising_stage(ctx):
        raise RuntimeError("simulated stage crash")

    monkeypatch.setattr("app.api.chat.PRE_CALL_STAGES", [budget_check_stage, _raising_stage])

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 503
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert spend is None or Decimal(spend) == Decimal("0")


async def test_reservation_refunded_when_later_pre_call_stage_blocks(
    client, db_session, fake_redis, seeded_team_and_key, monkeypatch
):
    """budget_check_stage reserves and allows, then a later pre-call stage
    blocks the request (e.g. threat detection flags it) -> 422. The
    reservation made for this request must be refunded, not left stranded.
    """
    team, _ = seeded_team_and_key
    await _add_policy(db_session, team)

    async def _blocking_stage(ctx):
        return StageResult.block("simulated_block")

    monkeypatch.setattr("app.api.chat.PRE_CALL_STAGES", [budget_check_stage, _blocking_stage])

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 422
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert spend is None or Decimal(spend) == Decimal("0")


@respx.mock
async def test_reservation_refunded_when_usage_recording_stage_fails(
    client, db_session, fake_redis, seeded_team_and_key, monkeypatch
):
    """The provider call succeeds (so a reservation exists and the pipeline
    is past the point of no return on the provider side), but something
    inside usage_recording_stage itself blows up - e.g. a Redis blip during
    reconcile_reservation - *after* the UsageRecord was already committed to
    Postgres. StageFailure -> 503, and the reservation must still be
    refunded rather than permanently overstating spend.
    """
    team, _ = seeded_team_and_key
    await _add_policy(db_session, team)
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(200, json=_SUCCESSFUL_RESPONSE_JSON)
    )

    async def _raising_reconcile(*args, **kwargs):
        raise RuntimeError("simulated redis blip during reconcile")

    monkeypatch.setattr(
        "app.core.governance.usage_recorder.reconcile_reservation", _raising_reconcile
    )

    response = await client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {RAW_TEST_KEY}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 503
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert spend is None or Decimal(spend) == Decimal("0")
