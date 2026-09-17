"""Budget policy lookup and Redis-backed spend tracking.

Spend accounting uses a reserve-then-reconcile pattern so concurrent requests
against the same team's budget can't race past the limit: pre-call,
`reserve_and_check` atomically adds an *estimated* cost to the running spend
and checks it against the limit in a single Lua script - the same atomicity
guarantee `rate_limiter.py`'s token bucket relies on. A naive
read-spend-then-compare-then-later-write approach lets N concurrent requests
all read the same "under budget" value before any of them records its cost,
overshooting the limit by up to N requests' worth of spend.

Post-call, `reconcile_reservation` corrects the counter from the estimate to
the real cost once it's known. If a request never reaches that point (blocked
downstream, upstream error, pipeline failure), the caller must refund the
estimate via `release_reservation` or the counter permanently overstates
spend.

See project_plan/03-cost-usage-governance.md §2, §4.
"""
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import BudgetPeriod, BudgetPolicy

# Returning a bare Lua number in a reply gets coerced to a RESP integer by
# Redis (truncating decimals), so the spend total is returned as a string via
# tostring() and parsed back into a Decimal on the Python side.
_RESERVE_AND_CHECK_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local reservation = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local current = tonumber(redis.call('GET', key) or '0')
if current + reservation > limit then
    return {0, tostring(current)}
end

local new_total = redis.call('INCRBYFLOAT', key, reservation)
redis.call('EXPIRE', key, ttl)
return {1, tostring(new_total)}
"""

# Generous, well past any period length, so the key space doesn't grow
# unbounded but a running window's counter never expires mid-period.
_SPEND_TTL_SECONDS = 60 * 60 * 24 * 40


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


async def reserve_and_check(
    redis: Redis,
    team_id: UUID,
    period: BudgetPeriod,
    limit_usd: Decimal,
    reservation_usd: Decimal,
) -> tuple[bool, Decimal]:
    """Atomically add `reservation_usd` to the team's running spend and check
    the result against `limit_usd` in one step. Returns (allowed, new_total)
    - if not allowed, no spend was recorded (the script rolls back its own
    write by never applying it when over limit).
    """
    allowed_raw, total_raw = await redis.eval(
        _RESERVE_AND_CHECK_SCRIPT,
        1,
        spend_key(team_id, period),
        str(limit_usd),
        str(reservation_usd),
        _SPEND_TTL_SECONDS,
    )
    return bool(int(allowed_raw)), Decimal(total_raw)


async def reconcile_reservation(
    redis: Redis,
    team_id: UUID,
    period: BudgetPeriod,
    reservation_usd: Decimal,
    actual_usd: Decimal,
) -> None:
    """Correct the spend counter from the pre-call estimate to the real cost
    once it's known post-call."""
    delta = actual_usd - reservation_usd
    if delta != 0:
        await redis.incrbyfloat(spend_key(team_id, period), float(delta))


async def release_reservation(
    redis: Redis, team_id: UUID, period: BudgetPeriod, reservation_usd: Decimal
) -> None:
    """Refund a reservation that was never fulfilled - the request was
    blocked or failed somewhere downstream of the budget check, so no actual
    cost will ever be reconciled for it."""
    if reservation_usd != 0:
        await redis.incrbyfloat(spend_key(team_id, period), float(-reservation_usd))
