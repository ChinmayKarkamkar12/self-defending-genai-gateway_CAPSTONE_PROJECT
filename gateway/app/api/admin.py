"""Admin endpoints for cost/usage governance, consumed by the dashboard
(module 8). See project_plan/03-cost-usage-governance.md §5.
"""
from datetime import datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.governance.budget import get_budget_policy, get_current_spend
from app.core.governance.redis_client import get_redis
from app.db.models import BudgetPeriod, BudgetPolicy, UsageRecord
from app.db.session import get_db

router = APIRouter(prefix="/v1/admin")


class UsageRecordOut(BaseModel):
    id: UUID
    api_key_id: UUID
    team_id: UUID
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    timestamp: datetime

    model_config = {"from_attributes": True}


class BudgetPolicyOut(BaseModel):
    team_id: UUID
    period: BudgetPeriod
    limit_usd: Decimal
    rate_limit_rps: int
    current_spend_usd: Decimal
    remaining_usd: Decimal


class BudgetPolicyIn(BaseModel):
    period: BudgetPeriod
    limit_usd: Decimal
    rate_limit_rps: int


@router.get("/usage", response_model=list[UsageRecordOut])
async def get_usage(
    team_id: UUID,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> list[UsageRecord]:
    stmt = select(UsageRecord).where(UsageRecord.team_id == team_id)
    if from_ is not None:
        stmt = stmt.where(UsageRecord.timestamp >= from_)
    if to is not None:
        stmt = stmt.where(UsageRecord.timestamp <= to)
    stmt = stmt.order_by(UsageRecord.timestamp)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/budget/{team_id}", response_model=BudgetPolicyOut)
async def get_budget(
    team_id: UUID,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
    redis=Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> BudgetPolicyOut:
    policy = await get_budget_policy(db, team_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="no budget policy configured for this team")

    current_spend = await get_current_spend(redis, team_id, policy.period)
    return BudgetPolicyOut(
        team_id=policy.team_id,
        period=policy.period,
        limit_usd=policy.limit_usd,
        rate_limit_rps=policy.rate_limit_rps,
        current_spend_usd=current_spend,
        remaining_usd=policy.limit_usd - current_spend,
    )


@router.put("/budget/{team_id}", response_model=BudgetPolicyOut)
async def put_budget(
    team_id: UUID,
    body: BudgetPolicyIn,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
    redis=Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> BudgetPolicyOut:
    policy = await get_budget_policy(db, team_id)
    if policy is None:
        policy = BudgetPolicy(team_id=team_id)
        db.add(policy)

    policy.period = body.period
    policy.limit_usd = body.limit_usd
    policy.rate_limit_rps = body.rate_limit_rps
    await db.commit()
    await db.refresh(policy)

    current_spend = await get_current_spend(redis, team_id, policy.period)
    return BudgetPolicyOut(
        team_id=policy.team_id,
        period=policy.period,
        limit_usd=policy.limit_usd,
        rate_limit_rps=policy.rate_limit_rps,
        current_spend_usd=current_spend,
        remaining_usd=policy.limit_usd - current_spend,
    )
