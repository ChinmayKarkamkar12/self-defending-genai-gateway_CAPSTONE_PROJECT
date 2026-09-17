"""Cost/usage governance stage. See project_plan/03-cost-usage-governance.md §4.

Reads `ctx.metadata["db"]` and `ctx.metadata["redis"]`, populated by the
chat endpoint before the pipeline runs. A team with no configured
`BudgetPolicy` is unrestricted (ALLOW) - budgets are opt-in per team.
"""
from app.core.context import RequestContext, StageResult
from app.core.governance.budget import get_budget_policy, get_current_spend
from app.core.governance.rate_limiter import check_and_consume


async def budget_check_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]
    redis = ctx.metadata["redis"]

    policy = await get_budget_policy(db, ctx.team_id)
    if policy is None:
        return StageResult.allow()

    current_spend = await get_current_spend(redis, ctx.team_id, policy.period)
    if current_spend >= policy.limit_usd:
        return StageResult.block("budget_exceeded")

    allowed = await check_and_consume(redis, str(ctx.api_key_id), policy.rate_limit_rps)
    if not allowed:
        return StageResult.block("rate_limited")

    ctx.metadata["budget_remaining"] = str(policy.limit_usd - current_spend)
    return StageResult.allow()
