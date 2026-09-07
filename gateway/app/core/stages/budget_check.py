"""Cost/usage governance stage. No-op stub — implemented in module 3."""
from app.core.context import RequestContext, StageResult


async def budget_check_stage(ctx: RequestContext) -> StageResult:
    return StageResult.allow()
