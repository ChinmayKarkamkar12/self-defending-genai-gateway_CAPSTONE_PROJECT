"""PII redaction stage. No-op stub — implemented in module 4."""
from app.core.context import RequestContext, StageResult


async def pii_redaction_stage(ctx: RequestContext) -> StageResult:
    return StageResult.allow()
