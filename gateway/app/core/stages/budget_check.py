"""Cost/usage governance stage. See project_plan/03-cost-usage-governance.md §4.

Reads `ctx.metadata["db"]` and `ctx.metadata["redis"]`, populated by the
chat endpoint before the pipeline runs. A team with no configured
`BudgetPolicy` is unrestricted (ALLOW) - budgets are opt-in per team.

Spend is reserved atomically here using an *estimate* of the request's cost
(we don't yet know the provider's actual token usage) and reconciled to the
real cost post-call by `usage_recording_stage`. If the request never reaches
that stage - blocked downstream, upstream error, pipeline failure - the chat
endpoint must refund the reservation via `release_reservation`, or the
reservation left in `ctx.metadata["budget_reservation"]`/`["budget_period"]`
would permanently overstate the team's spend. See
app/core/governance/budget.py's module docstring for why a plain
read-then-check would race under concurrent requests.
"""
from decimal import Decimal

from app.core.context import RequestContext, StageResult
from app.core.governance.budget import get_budget_policy, release_reservation, reserve_and_check
from app.core.governance.pricing import UnknownPricingError, calculate_cost
from app.core.governance.rate_limiter import check_and_consume
from app.core.governance.token_counter import estimate_input_tokens

# Conservative worst-case output-token estimate when the request doesn't set
# `max_tokens` - used only to size the pre-call spend reservation, never the
# authoritative cost (that comes from the provider's own usage report).
_DEFAULT_MAX_TOKENS_ESTIMATE = 1024


async def budget_check_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]
    redis = ctx.metadata["redis"]

    policy = await get_budget_policy(db, ctx.team_id)
    if policy is None:
        return StageResult.allow()

    model = ctx.body.get("model", "")
    tokens_in_estimate = estimate_input_tokens(model, ctx.body.get("messages", []))
    tokens_out_estimate = ctx.body.get("max_tokens") or _DEFAULT_MAX_TOKENS_ESTIMATE
    try:
        reservation = calculate_cost(model, tokens_in_estimate, tokens_out_estimate)
    except UnknownPricingError:
        # Unpriced model: reserve nothing pre-call rather than blocking a
        # request purely because pricing.py hasn't been updated yet.
        reservation = Decimal("0")

    allowed, new_total = await reserve_and_check(
        redis, ctx.team_id, policy.period, policy.limit_usd, reservation
    )
    if not allowed:
        return StageResult.block("budget_exceeded")

    rate_ok = await check_and_consume(redis, str(ctx.api_key_id), policy.rate_limit_rps)
    if not rate_ok:
        await release_reservation(redis, ctx.team_id, policy.period, reservation)
        return StageResult.block("rate_limited")

    ctx.metadata["budget_reservation"] = reservation
    ctx.metadata["budget_period"] = policy.period
    ctx.metadata["budget_remaining"] = str(policy.limit_usd - new_total)
    return StageResult.allow()
