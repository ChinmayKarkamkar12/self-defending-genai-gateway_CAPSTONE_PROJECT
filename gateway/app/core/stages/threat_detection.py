"""Prompt injection / jailbreak detection stage. No-op stub — implemented in module 5."""
from app.core.context import RequestContext, StageResult


async def threat_detection_stage(ctx: RequestContext) -> StageResult:
    return StageResult.allow()
