"""Tamper-evident audit logging stage. No-op stub — implemented in module 7."""
from app.core.context import RequestContext, StageResult


async def audit_log_stage(ctx: RequestContext) -> StageResult:
    return StageResult.allow()
