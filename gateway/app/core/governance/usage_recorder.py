"""Post-call cost accounting. See project_plan/03-cost-usage-governance.md §4.

Runs after the provider responds, once actual `tokens_in`/`tokens_out` are
known - this is the authoritative accounting step, distinct from the
pre-call estimate `budget_check_stage` never needs. Writes a durable
`UsageRecord` and increments the team's Redis spend counter for the current
budget window.
"""
from app.core.context import RequestContext, StageResult
from app.core.governance.budget import get_budget_policy, record_spend
from app.core.governance.pricing import calculate_cost
from app.core.governance.token_counter import extract_usage
from app.db.models import UsageRecord


async def usage_recording_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]
    redis = ctx.metadata["redis"]
    response = ctx.metadata["provider_response"]
    model = ctx.body.get("model", "")

    tokens_in, tokens_out = extract_usage(response)
    cost_usd = calculate_cost(model, tokens_in, tokens_out)

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
        await record_spend(redis, ctx.team_id, policy.period, cost_usd)

    return StageResult.allow()
