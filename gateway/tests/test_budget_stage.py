from decimal import Decimal

from app.core.context import Decision, RequestContext
from app.core.stages.budget_check import budget_check_stage
from app.db.models import BudgetPeriod, BudgetPolicy


def make_ctx(team_id, api_key_id, db, redis) -> RequestContext:
    ctx = RequestContext(body={"model": "gpt-4o"}, api_key_id=api_key_id, team_id=team_id)
    ctx.metadata["db"] = db
    ctx.metadata["redis"] = redis
    return ctx


async def test_allows_when_no_policy_configured(db_session, fake_redis, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    ctx = make_ctx(team.id, api_key.id, db_session, fake_redis)

    result = await budget_check_stage(ctx)

    assert result.decision == Decision.ALLOW


async def test_allows_when_under_budget(db_session, fake_redis, seeded_team_and_key):
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
    await fake_redis.set(f"budget:{team.id}:{_today_key()}", "1.00")

    ctx = make_ctx(team.id, api_key.id, db_session, fake_redis)
    result = await budget_check_stage(ctx)

    assert result.decision == Decision.ALLOW
    assert ctx.metadata["budget_remaining"] == "9.00"


async def test_blocks_when_over_budget(db_session, fake_redis, seeded_team_and_key):
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
    await fake_redis.set(f"budget:{team.id}:{_today_key()}", "10.00")

    ctx = make_ctx(team.id, api_key.id, db_session, fake_redis)
    result = await budget_check_stage(ctx)

    assert result.decision == Decision.BLOCK
    assert result.reason == "budget_exceeded"


async def test_blocks_when_rate_limited(db_session, fake_redis, seeded_team_and_key):
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


def _today_key() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%d")
