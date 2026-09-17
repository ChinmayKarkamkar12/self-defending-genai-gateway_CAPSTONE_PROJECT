"""Post-call cost accounting. See project_plan/03-cost-usage-governance.md §4.

Runs after the provider responds, once actual `tokens_in`/`tokens_out` are
known - this is the authoritative accounting step, distinct from the
pre-call estimate `budget_check_stage` uses to size its spend reservation.
Writes a durable `UsageRecord` and reconciles the team's Redis spend counter
from the pre-call estimate to the real cost. Pops `ctx.metadata["budget_reservation"]`/
`["budget_period"]` once consumed, so it's impossible for a later stage or
the chat endpoint to accidentally call `release_reservation` again on an
already-reconciled request and double-subtract the spend counter.

An unpriced model (pricing.py hasn't been updated yet) does not block an
already-successful response - the provider has already answered, so failing
the request now would throw away a good result over a bookkeeping gap. The
`UsageRecord` is still written (with cost 0) so the gap is visible in the
usage data, and a warning is logged.
"""
import logging
from decimal import Decimal

from app.core.context import RequestContext, StageResult
from app.core.governance.budget import get_budget_policy, reconcile_reservation
from app.core.governance.pricing import UnknownPricingError, calculate_cost
from app.core.governance.token_counter import extract_usage
from app.db.models import UsageRecord

logger = logging.getLogger("gateway.governance.usage")


async def usage_recording_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]
    redis = ctx.metadata["redis"]
    response = ctx.metadata["provider_response"]
    model = ctx.body.get("model", "")

    tokens_in, tokens_out = extract_usage(response)
    try:
        cost_usd = calculate_cost(model, tokens_in, tokens_out)
    except UnknownPricingError:
        logger.warning("no pricing entry for model '%s'; recording cost as 0", model)
        cost_usd = Decimal("0")

    db.add(
        UsageRecord(
            api_key_id=ctx.api_key_id,
            team_id=ctx.team_id,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost_usd,
        )
    )
    await db.commit()

    policy = await get_budget_policy(db, ctx.team_id)
    if policy is not None:
        reservation = ctx.metadata.get("budget_reservation", Decimal("0"))
        # Only pop once reconcile_reservation actually succeeds - if it
        # raises, the reservation must still be visible in ctx.metadata so
        # the chat endpoint's exception handler can refund it via
        # release_reservation instead of leaking it.
        await reconcile_reservation(redis, ctx.team_id, policy.period, reservation, cost_usd)
        ctx.metadata.pop("budget_reservation", None)
        ctx.metadata.pop("budget_period", None)

    return StageResult.allow()
