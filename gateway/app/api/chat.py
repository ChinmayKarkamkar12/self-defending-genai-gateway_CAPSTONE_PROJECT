"""POST /v1/chat/completions — auth -> pipeline -> provider -> response.

See project_plan/02-gateway-core-proxy.md §3.

Every authenticated request gets an audit entry (module 7), whichever way
it leaves: `_process` marks the outcome on each exit path in
`ctx.metadata["audit_outcome"]`, and `chat_completions` queues the entry
once `_process` returns or raises. A request rejected at authentication
(401) has no team or key to attribute it to and is not audited
(LIMITATIONS.md L7-5).
"""
import logging
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.entry import classify_block
from app.core.auth import authenticate
from app.core.context import Decision, RequestContext
from app.core.governance.budget import release_reservation
from app.core.governance.redis_client import get_redis
from app.core.pipeline import (
    POST_CALL_STAGES,
    PRE_CALL_STAGES,
    StageFailure,
    run_audit_log,
    run_defense_feedback,
    run_session_policy,
    run_stages,
    run_usage_recording,
)
from app.core.providers.base import UpstreamProviderError
from app.core.providers.registry import UnknownModelError, get_provider
from app.db.models import AuditOutcome
from app.db.session import get_db

logger = logging.getLogger("gateway.chat")

router = APIRouter()

PIPELINE_UNAVAILABLE_DETAIL = "a required pipeline component is unavailable"


async def _require_api_key(
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed Authorization header")
    raw_key = authorization.removeprefix("Bearer ").strip()
    api_key = await authenticate(raw_key, db)
    if api_key is None:
        raise HTTPException(status_code=401, detail="invalid or revoked API key")
    return api_key


async def _release_budget_reservation(ctx: RequestContext) -> None:
    """Refund a pre-call budget reservation for a request that will never
    reach `run_usage_recording` to reconcile it - otherwise the reservation
    permanently overstates the team's spend. No-op if budget_check_stage
    never reserved anything (no policy configured for the team).
    """
    period = ctx.metadata.get("budget_period")
    if period is None:
        return
    # Popped (like usage_recorder does) so the reservation can't be refunded twice.
    ctx.metadata.pop("budget_period", None)
    reservation = ctx.metadata.pop("budget_reservation", Decimal("0"))
    try:
        await release_reservation(ctx.metadata["redis"], ctx.team_id, period, reservation)
    except Exception:  # noqa: BLE001 - best-effort refund, must not mask the real error
        logger.error("failed to release budget reservation for team %s", ctx.team_id)


def _mark(ctx: RequestContext, outcome: AuditOutcome, stage: str | None = None) -> None:
    ctx.metadata["audit_outcome"] = outcome
    if stage is not None:
        ctx.metadata["audit_stage"] = stage


async def _process(ctx: RequestContext) -> Any:
    """Pipeline -> provider -> pipeline. Returns the provider response, or
    raises HTTPException with the outcome marked for the audit entry."""
    try:
        pre_result = await run_stages(PRE_CALL_STAGES, ctx)
        # Allowed or blocked, the session agent sees what 6a did.
        await run_session_policy(ctx)
    except StageFailure as exc:
        _mark(ctx, AuditOutcome.PIPELINE_ERROR, exc.stage_name)
        await _release_budget_reservation(ctx)
        raise HTTPException(status_code=503, detail=PIPELINE_UNAVAILABLE_DETAIL) from None

    if pre_result.decision == Decision.BLOCK:
        _mark(ctx, classify_block(ctx, pre_result.reason), ctx.metadata.get("blocked_by"))
        await _release_budget_reservation(ctx)
        raise HTTPException(status_code=422, detail=pre_result.reason or "blocked by pipeline")

    model = ctx.body.get("model", "")
    try:
        provider = get_provider(model)
    except UnknownModelError as exc:
        _mark(ctx, AuditOutcome.REJECTED_UNKNOWN_MODEL)
        await _release_budget_reservation(ctx)
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        response = await provider.chat_completion(ctx.body)
    except UpstreamProviderError as exc:
        _mark(ctx, AuditOutcome.UPSTREAM_ERROR)
        await _release_budget_reservation(ctx)
        raise HTTPException(status_code=502, detail=f"upstream provider error: {exc}") from exc

    ctx.metadata["provider_response"] = response

    try:
        await run_usage_recording(ctx)
    except StageFailure as exc:
        _mark(ctx, AuditOutcome.PIPELINE_ERROR, exc.stage_name)
        await _release_budget_reservation(ctx)
        raise HTTPException(status_code=503, detail=PIPELINE_UNAVAILABLE_DETAIL) from None

    try:
        post_result = await run_stages(POST_CALL_STAGES, ctx)
    except StageFailure as exc:
        _mark(ctx, AuditOutcome.PIPELINE_ERROR, exc.stage_name)
        raise HTTPException(status_code=503, detail=PIPELINE_UNAVAILABLE_DETAIL) from None

    # Runs before acting on post_result: a response output_scan blocks is
    # the case the bandit most needs to hear about.
    try:
        await run_defense_feedback(ctx)
    except StageFailure as exc:
        _mark(ctx, AuditOutcome.PIPELINE_ERROR, exc.stage_name)
        raise HTTPException(status_code=503, detail=PIPELINE_UNAVAILABLE_DETAIL) from None

    if post_result.decision == Decision.BLOCK:
        _mark(ctx, classify_block(ctx, post_result.reason), ctx.metadata.get("blocked_by"))
        detail = post_result.reason or "response blocked by pipeline"
        raise HTTPException(status_code=422, detail=detail)

    _mark(ctx, AuditOutcome.ALLOWED)
    return response


async def _audit_refused_request(ctx: RequestContext, status_code: int) -> None:
    """Audit a request that is already failing. A failure to queue the
    entry is logged but must not replace the error the client gets."""
    ctx.metadata["audit_http_status"] = status_code
    try:
        await run_audit_log(ctx)
    except StageFailure as exc:
        logger.error("audit logging failed for a refused request: %s", exc)


@router.post("/v1/chat/completions")
async def chat_completions(
    body: dict[str, Any],
    api_key=Depends(_require_api_key),  # noqa: B008 - standard FastAPI DI pattern
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
    redis: Redis = Depends(get_redis),  # noqa: B008 - standard FastAPI DI pattern
) -> Any:
    request_id = str(uuid.uuid4())
    ctx = RequestContext(body=body, api_key_id=api_key.id, team_id=api_key.team_id)
    ctx.metadata["db"] = db
    ctx.metadata["redis"] = redis
    ctx.metadata["request_id"] = request_id
    ctx.metadata["received_at"] = datetime.now(UTC)
    ctx.metadata["started_monotonic"] = time.perf_counter()

    try:
        response = await _process(ctx)
    except HTTPException as exc:
        await _audit_refused_request(ctx, exc.status_code)
        # Refused requests carry their ID too, so a client can quote it and
        # an admin can find the matching audit entry.
        exc.headers = {**(exc.headers or {}), "x-gateway-request-id": request_id}
        raise
    except Exception:
        _mark(ctx, AuditOutcome.INTERNAL_ERROR)
        # No-op if the reservation was already refunded or reconciled.
        await _release_budget_reservation(ctx)
        await _audit_refused_request(ctx, 500)
        raise

    # A successful response is only returned once its audit entry is queued.
    ctx.metadata["audit_http_status"] = 200
    try:
        await run_audit_log(ctx)
    except StageFailure as exc:
        logger.error("audit logging failed: %s", exc)
        raise HTTPException(status_code=503, detail=PIPELINE_UNAVAILABLE_DETAIL) from None

    headers = {"x-gateway-request-id": request_id}
    if "budget_remaining" in ctx.metadata:
        headers["x-gateway-budget-remaining"] = ctx.metadata["budget_remaining"]
    return JSONResponse(content=response, headers=headers)
