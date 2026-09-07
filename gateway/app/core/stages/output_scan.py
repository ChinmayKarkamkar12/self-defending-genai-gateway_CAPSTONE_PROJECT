"""Provider-response scanning stage (post-call). No-op stub — implemented alongside module 5/6."""
from app.core.context import RequestContext, StageResult


async def output_scan_stage(ctx: RequestContext) -> StageResult:
    return StageResult.allow()
