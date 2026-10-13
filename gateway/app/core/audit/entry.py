"""Assembles one audit record from what the pipeline stages left in
`ctx.metadata`. See project_plan/07-audit-logging.md §4 step 1.

Every value copied here is a fixed category, a count, a score, an ID or a
number: never prompt or response text, never a block reason or error
message (those can carry client or provider text), never a raw PII value.
test_redaction_summary.py checks this against module 4's fixture PII.

The chat endpoint sets `ctx.metadata["audit_outcome"]` (and, when a stage
blocked or failed the request, `["audit_stage"]`) on every exit path; the
pipeline records which stage blocked in `["blocked_by"]`.
"""
import re
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from app.core.context import RequestContext
from app.core.providers.registry import UnknownModelError, get_provider
from app.db.models import AuditOutcome, DefenseAction

NOT_EVALUATED = "not_evaluated"
UNRECOGNIZED_MODEL = "<unrecognized>"

# The model name is client-supplied text. Only a plain identifier that
# routes to a real provider is kept; anything else (which could be any
# text at all, PII included) is stored as UNRECOGNIZED_MODEL.
_MODEL_NAME = re.compile(r"[A-Za-z0-9._:/-]{1,100}")

# Stage name -> outcome, for a pre/post-call stage that returned BLOCK.
# budget_check and bandit_policy have more than one kind of block; see
# classify_block.
_BLOCK_OUTCOMES = {
    "session_guard_stage": AuditOutcome.BLOCKED_SESSION_LOCKED,
    "output_scan_stage": AuditOutcome.BLOCKED_OUTPUT_LEAK,
}


def safe_model_name(model: Any) -> str:
    if not isinstance(model, str) or not _MODEL_NAME.fullmatch(model):
        return UNRECOGNIZED_MODEL
    try:
        get_provider(model)
    except UnknownModelError:
        return UNRECOGNIZED_MODEL
    return model


def classify_block(ctx: RequestContext, reason: str | None) -> AuditOutcome:
    """Outcome for a request a stage returned BLOCK for. `reason` is only
    compared against the stages' fixed reason constants, never stored."""
    stage = ctx.metadata.get("blocked_by")
    if stage in _BLOCK_OUTCOMES:
        return _BLOCK_OUTCOMES[stage]
    if stage == "budget_check_stage":
        return AuditOutcome.BLOCKED_RATE_LIMIT if reason == "rate_limited" else (
            AuditOutcome.BLOCKED_BUDGET
        )
    if stage == "bandit_policy_stage":
        defense = ctx.metadata.get("defense") or {}
        if defense.get("outcome") == DefenseAction.ESCALATE_TO_HUMAN.value:
            return AuditOutcome.ESCALATED
        return AuditOutcome.BLOCKED_THREAT
    # A stage added later without an entry above still gets audited.
    return AuditOutcome.BLOCKED_THREAT


def _threat_score(value: Any) -> dict[str, float] | None:
    if not isinstance(value, dict):
        return None
    return {str(k): float(v) for k, v in value.items()}


def _redaction_summary(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(k): int(v) for k, v in value.items()}


def _output_flags(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    # output_scan lists the echoed tokens themselves; a count is enough here.
    return {
        "system_prompt_leaked": bool(value.get("system_prompt_leaked", False)),
        "echoed_redaction_tokens": len(value.get("echoed_redaction_tokens") or []),
    }


def build_audit_record(ctx: RequestContext) -> dict[str, Any]:
    """Column values for an AuditLogEntry, minus sequence_number and the
    two hashes, which the writer assigns when it chains the entry."""
    meta = ctx.metadata
    defense = meta.get("defense") or {}
    session_policy = meta.get("session_policy") or {}
    usage = meta.get("usage") or {}
    started = meta.get("started_monotonic")
    latency_ms = int((time.perf_counter() - started) * 1000) if started is not None else 0
    threat_event_id = defense.get("threat_event_id")

    return {
        "id": uuid.uuid4(),
        "timestamp": meta.get("received_at") or datetime.now(UTC),
        "request_id": uuid.UUID(str(meta["request_id"])),
        "team_id": ctx.team_id,
        "api_key_id": ctx.api_key_id,
        "model": safe_model_name(ctx.body.get("model")),
        "http_status": int(meta.get("audit_http_status", 200)),
        # The chat endpoint marks every exit path; an unmarked one is a
        # wiring bug, recorded as an error rather than guessed as allowed.
        "outcome": AuditOutcome(meta.get("audit_outcome", AuditOutcome.INTERNAL_ERROR)),
        "pipeline_stage": meta.get("audit_stage"),
        "redaction_summary": _redaction_summary(meta.get("redaction_map")),
        "threat_score": _threat_score(meta.get("threat_score")),
        "action_taken": str(defense.get("outcome") or NOT_EVALUATED),
        "threat_event_id": uuid.UUID(str(threat_event_id)) if threat_event_id else None,
        "session_id": meta.get("session_id"),
        "session_action": session_policy.get("action"),
        "output_flags": _output_flags(meta.get("output_flags")),
        "tokens_in": int(usage.get("tokens_in", 0)),
        "tokens_out": int(usage.get("tokens_out", 0)),
        "cost_usd": Decimal(str(usage.get("cost_usd", "0"))),
        "latency_ms": max(latency_ms, 0),
    }
