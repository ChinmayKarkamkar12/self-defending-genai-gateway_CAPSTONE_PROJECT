"""Admin endpoints for the session agent (module 6b), consumed by the
dashboard (module 8). See project_plan/06b-adaptive-defense-rl-session-agent.md
§7 task 11.

Same caveat as every /v1/admin route today (LIMITATIONS.md L3-1): no admin
authentication until module 8 - in particular, anyone who can reach the
gateway can lift a lockout.
"""
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.defense.escalation import challenge_pending, read_escalation_bias
from app.core.defense.features import attack_probability
from app.core.defense.session import current_session, is_locked, unlock
from app.core.governance.redis_client import get_redis
from app.db.models import DefenseAction, SessionAction, SessionPolicyEvent, ThreatEvent
from app.db.session import get_db

router = APIRouter(prefix="/v1/admin/sessions")


class RequestPoint(BaseModel):
    at: datetime
    attack_probability: float
    action: DefenseAction
    outcome: DefenseAction
    escalation_bias: float
    forced_escalation: bool


class PolicyPoint(BaseModel):
    at: datetime
    policy: str
    proposed_action: SessionAction
    action: SessionAction
    bias_before: float
    bias_after: float
    request_count: int
    score_mean: float
    score_max: float
    consecutive_refused: float


class LiveState(BaseModel):
    active: bool
    escalation_bias: float
    challenge_pending: bool
    locked: bool


class RiskTrendOut(BaseModel):
    session_id: str
    team_id: UUID
    api_key_id: UUID
    requests: list[RequestPoint]
    policy_runs: list[PolicyPoint]
    live: LiveState


class SessionSummary(BaseModel):
    session_id: str
    team_id: UUID
    api_key_id: UUID
    first_at: datetime
    last_at: datetime
    policy_runs: int
    last_action: SessionAction
    last_bias: float


class UnlockOut(BaseModel):
    api_key_id: UUID
    was_locked: bool


def _as_utc(value: datetime) -> datetime:
    # SQLite (the test database) drops tzinfo; Postgres keeps it.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.get("", response_model=list[SessionSummary])
async def list_sessions(
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[SessionSummary]:
    """Most recently active sessions, newest first."""
    rows = (
        await db.execute(
            select(SessionPolicyEvent).order_by(SessionPolicyEvent.created_at.desc()).limit(5000)
        )
    ).scalars()
    summaries: dict[str, SessionSummary] = {}
    for row in rows:
        at = _as_utc(row.created_at)
        summary = summaries.get(row.session_id)
        if summary is None:
            if len(summaries) >= limit:
                continue
            summaries[row.session_id] = SessionSummary(
                session_id=row.session_id,
                team_id=row.team_id,
                api_key_id=row.api_key_id,
                first_at=at,
                last_at=at,
                policy_runs=1,
                last_action=row.action,
                last_bias=row.bias_after,
            )
        else:
            summary.first_at = min(summary.first_at, at)
            summary.policy_runs += 1
    return list(summaries.values())


@router.get("/{session_id}/risk-trend", response_model=RiskTrendOut)
async def risk_trend(
    session_id: str,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
    redis: Redis = Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> RiskTrendOut:
    """Per-request scores and 6a decisions, and every session-agent run,
    oldest first, plus the session's live state in Redis."""
    events = (
        await db.execute(
            select(ThreatEvent)
            .where(ThreatEvent.session_id == session_id)
            .order_by(ThreatEvent.created_at)
        )
    ).scalars().all()
    runs = (
        await db.execute(
            select(SessionPolicyEvent)
            .where(SessionPolicyEvent.session_id == session_id)
            .order_by(SessionPolicyEvent.created_at)
        )
    ).scalars().all()
    if not events and not runs:
        raise HTTPException(status_code=404, detail="session not found")
    owner = events[0] if events else runs[0]

    return RiskTrendOut(
        session_id=session_id,
        team_id=owner.team_id,
        api_key_id=owner.api_key_id,
        requests=[
            RequestPoint(
                at=_as_utc(e.created_at),
                attack_probability=attack_probability(e.threat_score),
                action=e.action_taken,
                outcome=e.outcome or e.action_taken,
                escalation_bias=e.escalation_bias,
                forced_escalation=bool(e.forced_escalation),
            )
            for e in events
        ],
        policy_runs=[
            PolicyPoint(
                at=_as_utc(r.created_at),
                policy=r.policy,
                proposed_action=r.proposed_action,
                action=r.action,
                bias_before=r.bias_before,
                bias_after=r.bias_after,
                request_count=r.request_count,
                score_mean=float(r.features.get("score_mean", 0.0)),
                score_max=float(r.features.get("score_max", 0.0)),
                consecutive_refused=float(r.features.get("consecutive_refused", 0.0)),
            )
            for r in runs
        ],
        live=LiveState(
            active=await current_session(redis, owner.api_key_id) == session_id,
            escalation_bias=await read_escalation_bias(redis, session_id),
            challenge_pending=await challenge_pending(redis, session_id),
            locked=await is_locked(redis, owner.api_key_id),
        ),
    )


@router.post("/unlock/{api_key_id}", response_model=UnlockOut)
async def unlock_api_key(
    api_key_id: UUID,
    redis: Redis = Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> UnlockOut:
    """Lift a session lockout early. Also ends the key's current session, so
    its next request starts with neutral session state."""
    return UnlockOut(api_key_id=api_key_id, was_locked=await unlock(redis, api_key_id))
