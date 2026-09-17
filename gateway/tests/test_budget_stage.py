import asyncio
from datetime import UTC, datetime
from decimal import Decimal

from app.core.context import Decision, RequestContext
from app.core.governance.budget import get_current_spend, reconcile_reservation
from app.core.stages.budget_check import budget_check_stage
from app.db.models import BudgetPeriod, BudgetPolicy


def make_ctx(team_id, api_key_id, db, redis, *, max_tokens=None) -> RequestContext:
    # Empty content -> tiktoken estimates 0 input tokens, so the reservation
    # is driven purely by `max_tokens` and stays exactly predictable in tests.
    body: dict = {"model": "gpt-4o", "messages": [{"role": "user", "content": ""}]}
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    ctx = RequestContext(body=body, api_key_id=api_key_id, team_id=team_id)
    ctx.metadata["db"] = db
    ctx.metadata["redis"] = redis
    return ctx


def _today_key() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


async def test_allows_when_no_policy_configured(db_session, fake_redis, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    ctx = make_ctx(team.id, api_key.id, db_session, fake_redis)

    result = await budget_check_stage(ctx)

    assert result.decision == Decision.ALLOW
    assert "budget_reservation" not in ctx.metadata


async def test_allows_when_under_budget_and_reserves_estimate(
    db_session, fake_redis, seeded_team_and_key
):
    team, api_key = seeded_team_and_key
    db_session.add(
        BudgetPolicy(
            team_id=team.id,
            period=BudgetPeriod.DAILY,
            limit_usd=Decimal("10.00"),
            rate_limit_rps=100,
        )
    )
    await db_session.commit()

    ctx = make_ctx(team.id, api_key.id, db_session, fake_redis, max_tokens=1000)
    result = await budget_check_stage(ctx)

    assert result.decision == Decision.ALLOW
    # Something non-zero was reserved and actually written to Redis.
    reservation = ctx.metadata["budget_reservation"]
    assert reservation > 0
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert Decimal(spend) == reservation


async def test_blocks_when_over_budget_without_reserving(
    db_session, fake_redis, seeded_team_and_key
):
    team, api_key = seeded_team_and_key
    db_session.add(
        BudgetPolicy(
            team_id=team.id,
            period=BudgetPeriod.DAILY,
            limit_usd=Decimal("1.00"),
            rate_limit_rps=100,
        )
    )
    await db_session.commit()
    await fake_redis.set(f"budget:{team.id}:{_today_key()}", "1.00")

    ctx = make_ctx(team.id, api_key.id, db_session, fake_redis)
    result = await budget_check_stage(ctx)

    assert result.decision == Decision.BLOCK
    assert result.reason == "budget_exceeded"
    # A blocked request must not have moved the spend counter at all.
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert Decimal(spend) == Decimal("1.00")


async def test_blocks_when_rate_limited_and_refunds_reservation(
    db_session, fake_redis, seeded_team_and_key
):
    team, api_key = seeded_team_and_key
    db_session.add(
        BudgetPolicy(
            team_id=team.id,
            period=BudgetPeriod.DAILY,
            limit_usd=Decimal("10.00"),
            rate_limit_rps=1,
        )
    )
    await db_session.commit()

    ctx1 = make_ctx(team.id, api_key.id, db_session, fake_redis)
    ctx2 = make_ctx(team.id, api_key.id, db_session, fake_redis)

    first = await budget_check_stage(ctx1)
    second = await budget_check_stage(ctx2)

    assert first.decision == Decision.ALLOW
    assert second.decision == Decision.BLOCK
    assert second.reason == "rate_limited"
    # The second request's reservation must have been refunded, leaving only
    # the first request's reservation on the counter.
    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert Decimal(spend) == ctx1.metadata["budget_reservation"]


async def test_concurrent_requests_dont_overspend_budget(
    db_session, fake_redis, seeded_team_and_key
):
    """The race-condition check for the budget path, mirroring
    test_rate_limiter's concurrency test: fire many concurrent requests
    against a budget sized for only a few of them, and confirm the total
    reserved spend never exceeds the limit - a plain read-then-check would
    let every concurrent request through before any of them recorded spend.
    """
    team, api_key = seeded_team_and_key
    per_request_cost = Decimal("1.00")
    limit = per_request_cost * 3
    db_session.add(
        BudgetPolicy(
            team_id=team.id,
            period=BudgetPeriod.DAILY,
            limit_usd=limit,
            rate_limit_rps=1000,  # high enough that rate limiting isn't the bottleneck
        )
    )
    await db_session.commit()

    # max_tokens tuned so the reservation estimate is exactly $1.00 for gpt-4o
    # ($10/M output tokens -> 100_000 output tokens -> $1.00).
    contexts = [
        make_ctx(team.id, api_key.id, db_session, fake_redis, max_tokens=100_000)
        for _ in range(10)
    ]

    results = await asyncio.gather(*[budget_check_stage(ctx) for ctx in contexts])

    allowed = [r for r in results if r.decision == Decision.ALLOW]
    blocked = [r for r in results if r.decision == Decision.BLOCK]
    assert len(allowed) == 3
    assert len(blocked) == 7
    assert all(r.reason == "budget_exceeded" for r in blocked)

    spend = await fake_redis.get(f"budget:{team.id}:{_today_key()}")
    assert Decimal(spend) <= limit


async def test_concurrent_reconciles_dont_lose_updates(
    db_session, fake_redis, seeded_team_and_key
):
    """Regression test for reconcile_reservation specifically, mirroring the
    reserve-side concurrency test above.

    reconcile_reservation applies a precomputed delta via a single
    INCRBYFLOAT, not a GET-then-SET, so it should already be race-free - but
    a naive read-modify-write reimplementation would lose updates under
    concurrency the same way the original budget_check_stage bug did: many
    readers see the same starting value, compute their own "corrected"
    total independently, and the last writer wins, silently discarding every
    other reconcile. Firing many concurrent reconciles with distinct deltas
    and checking the final total against the exact expected sum catches
    that regardless of which one loses.
    """
    team, _ = seeded_team_and_key
    key = f"budget:{team.id}:{_today_key()}"
    starting_spend = Decimal("5.00")
    await fake_redis.set(key, str(starting_spend))

    # each reconcile corrects a $1.00 reservation down to a distinct actual
    # cost, so every delta is different and none can coincidentally cancel
    # out a lost update
    deltas = [Decimal(f"0.{i:02d}") - Decimal("1.00") for i in range(10)]

    await asyncio.gather(
        *[
            reconcile_reservation(
                fake_redis, team.id, BudgetPeriod.DAILY, Decimal("1.00"), Decimal(f"0.{i:02d}")
            )
            for i in range(10)
        ]
    )

    final_spend = await get_current_spend(fake_redis, team.id, BudgetPeriod.DAILY)
    expected = starting_spend + sum(deltas)
    # INCRBYFLOAT does float arithmetic server-side, so the last few binary
    # digits are noise, not a lost update - quantize to the same 6dp
    # precision the rest of the system's costs are rounded to.
    assert final_spend.quantize(Decimal("0.000001")) == expected.quantize(Decimal("0.000001"))
