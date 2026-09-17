"""Budget policy lookup and Redis-backed spend tracking.

See project_plan/03-cost-usage-governance.md §2, §4.
"""
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import BudgetPeriod, BudgetPolicy


async def get_budget_policy(db: AsyncSession, team_id: UUID) -> BudgetPolicy | None:
    result = await db.execute(select(BudgetPolicy).where(BudgetPolicy.team_id == team_id))
    return result.scalar_one_or_none()


def period_key(period: BudgetPeriod, now: datetime | None = None) -> str:
    """Bucket identifier for the current period window, e.g. '2026-09-17' for
    daily or '2026-09' for monthly. Used as the Redis key suffix so spend
    naturally resets when the window rolls over.
    """
    now = now or datetime.now(UTC)
    if period == BudgetPeriod.DAILY:
        return now.strftime("%Y-%m-%d")
    return now.strftime("%Y-%m")


def spend_key(team_id: UUID, period: BudgetPeriod, now: datetime | None = None) -> str:
    return f"budget:{team_id}:{period_key(period, now)}"


async def get_current_spend(redis: Redis, team_id: UUID, period: BudgetPeriod) -> Decimal:
    raw = await redis.get(spend_key(team_id, period))
    return Decimal(raw) if raw is not None else Decimal("0")


async def record_spend(
    redis: Redis, team_id: UUID, period: BudgetPeriod, cost_usd: Decimal
) -> None:
    key = spend_key(team_id, period)
    await redis.incrbyfloat(key, float(cost_usd))
    # Ensure the counter for this window eventually expires so the key space
    # doesn't grow unbounded; a generous TTL well past any period length.
    await redis.expire(key, 60 * 60 * 24 * 40)
