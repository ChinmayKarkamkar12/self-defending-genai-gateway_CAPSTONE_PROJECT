"""Fixed-order pipeline stage runner. See project_plan/02-gateway-core-proxy.md §4, §6.

Stage order (pre-call -> provider call -> post-call -> audit):
    [session_guard, budget_check, threat_detection, pii_redaction, bandit_policy]
    -> session_policy -> provider_call
    -> usage_recording -> [output_scan] -> defense_feedback -> [audit_log]

session_guard (module 6b) goes first: a locked API key is refused before
anything is spent on it, and the session ID it sets is what bandit_policy
reads the session's escalation_bias and challenge flag with.
session_policy (module 6b) runs once the pre-call stages are done, whether
they allowed or blocked the request - a refused request is exactly what the
session agent needs to see. It never blocks; it shapes the next request.

bandit_policy (module 6a) is the only pre-call stage that turns the threat
score into an action - see app/core/stages/bandit_policy.py for why it
runs after pii_redaction. defense_feedback runs after output_scan
whatever output_scan decided, because a leak output_scan blocks on is
exactly the evidence the bandit needs to learn from.

`usage_recording` runs unconditionally right after the provider responds,
before output_scan - cost was already incurred with the provider regardless
of what output_scan decides, so accounting must not be skippable by a later
stage's BLOCK. See project_plan/03-cost-usage-governance.md §4.

Every stage call is wrapped in try/except. On an exception:
  - FAIL_MODE=closed (default) -> the stage is treated as BLOCK (503 to the caller)
  - FAIL_MODE=open             -> a warning is logged, the stage is treated as ALLOW

This is the fail-open/fail-closed decision from ADR-0001.
"""
import logging
from typing import Protocol

from app.config import settings
from app.core.context import Decision, RequestContext, StageResult
from app.core.defense.feedback import defense_feedback_stage
from app.core.governance.usage_recorder import usage_recording_stage
from app.core.stages.audit_log import audit_log_stage
from app.core.stages.bandit_policy import bandit_policy_stage
from app.core.stages.budget_check import budget_check_stage
from app.core.stages.output_scan import output_scan_stage
from app.core.stages.pii_redaction import pii_redaction_stage
from app.core.stages.session_guard import session_guard_stage
from app.core.stages.session_policy import session_policy_stage
from app.core.stages.threat_detection import threat_detection_stage

logger = logging.getLogger("gateway.pipeline")


class PipelineStage(Protocol):
    async def __call__(self, ctx: RequestContext) -> StageResult:
        """Return ALLOW, BLOCK, or MODIFY(new_payload)."""
        ...


PRE_CALL_STAGES: list[PipelineStage] = [
    session_guard_stage,
    budget_check_stage,
    threat_detection_stage,
    pii_redaction_stage,
    bandit_policy_stage,
]

POST_CALL_STAGES: list[PipelineStage] = [
    output_scan_stage,
]


class StageFailure(Exception):
    """Raised internally when a stage errors under FAIL_MODE=closed."""

    def __init__(self, stage_name: str, original: Exception):
        self.stage_name = stage_name
        self.original = original
        super().__init__(f"stage '{stage_name}' failed: {original}")


async def _run_stage(stage: PipelineStage, ctx: RequestContext) -> StageResult:
    stage_name = getattr(stage, "__name__", repr(stage))
    try:
        return await stage(ctx)
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see ADR-0001
        if settings.FAIL_MODE == "open":
            logger.warning("stage %s raised %r; FAIL_MODE=open, treating as ALLOW", stage_name, exc)
            return StageResult.allow()
        logger.error("stage %s raised %r; FAIL_MODE=closed, blocking request", stage_name, exc)
        raise StageFailure(stage_name, exc) from exc


async def run_stages(stages: list[PipelineStage], ctx: RequestContext) -> StageResult:
    """Run `stages` in order against `ctx`, short-circuiting on BLOCK.

    MODIFY results update `ctx.body` in place and execution continues.
    """
    for stage in stages:
        result = await _run_stage(stage, ctx)
        if result.decision == Decision.BLOCK:
            return result
        if result.decision == Decision.MODIFY and result.modified_body is not None:
            ctx.body = result.modified_body
    return StageResult.allow()


async def run_usage_recording(ctx: RequestContext) -> None:
    """Best-effort-under-FAIL_MODE=open, fail-closed-by-default post-call
    cost accounting. See module docstring for why this isn't a POST_CALL_STAGE.
    """
    await _run_stage(usage_recording_stage, ctx)


async def run_session_policy(ctx: RequestContext) -> None:
    """Module 6b's session policy step, after the pre-call stages. Never
    blocks on its own; errors follow FAIL_MODE like every other stage."""
    await _run_stage(session_policy_stage, ctx)


async def run_defense_feedback(ctx: RequestContext) -> None:
    """Post-call bandit feedback (module 6a). Never blocks on its own;
    errors follow FAIL_MODE like every other stage."""
    await _run_stage(defense_feedback_stage, ctx)


async def run_audit_log(ctx: RequestContext) -> None:
    """Best-effort audit log call; never raises under FAIL_MODE=open, still
    honors FAIL_MODE=closed by re-raising so the caller can decide.
    """
    await _run_stage(audit_log_stage, ctx)
