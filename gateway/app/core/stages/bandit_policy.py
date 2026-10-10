"""Tactical defense stage: the contextual bandit's per-request decision.
See project_plan/06a-adaptive-defense-bandit.md §5.

Runs last in PRE_CALL_STAGES, after pii_redaction_stage - not straight
after threat_detection_stage as the module plan first sketched - for two
reasons:

  - the PII entity count is one of the bandit's features, and only exists
    once module 4 has run;
  - everything this stage stores or re-scans (the review excerpt, the
    redact_and_allow re-scan) is then post-redaction text, so raw PII
    never reaches the review queue.

threat_detection_stage never blocks, so running this later costs nothing:
it is still the one place a threat score turns into an action.

Steps:
  1. Build the context vector (app/core/defense/features.py).
  2. Read module 6b's escalation_bias for the session (neutral if none).
  3. Ask the bandit for an action, exploration included, with arms masked
     by bandit.safety_mask (allow above BANDIT_ALLOW_MASK_THRESHOLD or on a
     flagged system prompt plus a suspicious conversation, redact above
     BANDIT_REDACT_MASK_THRESHOLD). If module 6b's session agent left a
     `challenge` for this session, it is consumed and the request is
     escalated to human review instead, whatever the bandit chose
     (ThreatEvent.forced_escalation; arm_scores still show its choice).
  4. If the team already has BANDIT_REVIEW_TEAM_CAP items pending review,
     an escalation is carried out as a block (outcome=block) and no spot
     check is sampled - see review_queue.py.
  5. Record a ThreatEvent; queue a ReviewQueueItem for escalations and for
     a random spot-check sample of the other decisions.
  6. Map the action to a StageResult:
       allow            -> ALLOW
       redact_and_allow -> MODIFY (flagged windows cut, see strip.py), or
                           BLOCK if the stripped text still scores at or
                           above BANDIT_REDACT_WINDOW_THRESHOLD
       block            -> BLOCK
       escalate_to_human-> BLOCK while the request waits for review

Like the threat stage, any exception from the classifier during the
redact re-scan is re-raised as a type-name-only DefenseError, so the
pipeline's `repr(exc)` logging can't print request text.
"""
import asyncio
import logging
import random
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis

from app.config import settings
from app.core.context import RequestContext, StageResult
from app.core.defense.bandit import safety_mask
from app.core.defense.escalation import read_escalation_bias, take_challenge
from app.core.defense.features import (
    FEATURE_VERSION,
    FeatureInputs,
    attack_probability,
    build_features,
    features_to_dict,
    system_attack_probability,
)
from app.core.defense.review_queue import build_excerpt, enqueue, has_capacity
from app.core.defense.store import bandit_store
from app.core.defense.strip import StripResult, strip_flagged_content
from app.core.threat.classifier import get_threat_classifier
from app.db.models import DefenseAction, ReviewReason, ThreatEvent

logger = logging.getLogger("gateway.defense")

BLOCK_REASON = "request blocked by the adaptive defense policy"
ESCALATE_REASON = "request held for human review by the adaptive defense policy"

# Module-level so tests can seed it; only decides spot-check sampling.
spot_check_rng = random.Random()


class DefenseError(Exception):
    """Carries only the original exception's type name - see the
    threat stage's ThreatDetectionError for why."""

    def __init__(self, original_type: str):
        super().__init__(f"adaptive defense redaction failed ({original_type})")


async def _strip(body: dict, classifier) -> StripResult:
    failure_type: str | None = None
    try:
        result = await asyncio.to_thread(
            strip_flagged_content,
            body,
            classifier,
            settings.BANDIT_REDACT_WINDOW_THRESHOLD,
            settings.BANDIT_REDACT_MIN_WINDOW,
        )
    except Exception as exc:  # noqa: BLE001 - see DefenseError
        failure_type = type(exc).__name__
    # Raised outside the `except` block so the original exception isn't
    # attached as __context__ - see app/config.py's _load_settings.
    if failure_type is not None:
        logger.error("redact_and_allow failed (%s)", failure_type)
        raise DefenseError(failure_type)
    return result


async def bandit_policy_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]
    redis: Redis = ctx.metadata["redis"]
    # No score means module 5 didn't run - a wiring bug. KeyError fails
    # the request closed rather than deciding blind.
    threat_score = ctx.metadata["threat_score"]
    scan = ctx.metadata.get("threat_scan") or {}
    request_id = ctx.metadata.setdefault("request_id", str(uuid.uuid4()))
    now = datetime.now(UTC)

    inputs = FeatureInputs(
        threat_score=threat_score,
        system_prompt_threat_score=ctx.metadata.get("system_prompt_threat_score"),
        scan_windows=int(scan.get("windows", 1)),
        scan_truncated=bool(scan.get("truncated", False)),
        pii_entity_count=sum((ctx.metadata.get("redaction_map") or {}).values()),
    )
    x = build_features(inputs)
    session_id = ctx.metadata.get("session_id")
    bias = await read_escalation_bias(redis, session_id)

    masked = safety_mask(
        attack_probability(threat_score),
        settings.BANDIT_ALLOW_MASK_THRESHOLD,
        settings.BANDIT_REDACT_MASK_THRESHOLD,
        system_attack_probability(inputs),
    )

    bandit = await bandit_store.current(db)
    selection = bandit.select(
        x, alpha=settings.BANDIT_ALPHA, escalation_bias=bias, masked=masked
    )
    action = selection.action
    forced_escalation = await take_challenge(redis, session_id)
    if forced_escalation:
        action = DefenseAction.ESCALATE_TO_HUMAN

    review_reason: ReviewReason | None = None
    if action == DefenseAction.ESCALATE_TO_HUMAN:
        review_reason = ReviewReason.ESCALATION
    elif spot_check_rng.random() < settings.BANDIT_SPOT_CHECK_RATE:
        review_reason = ReviewReason.SPOT_CHECK
    # What actually happens to the request when it differs from `action`
    # (ThreatEvent.outcome - the reward follows the outcome).
    outcome: DefenseAction | None = None
    review_cap_reached = False
    if review_reason is not None and not await has_capacity(db, ctx.team_id):
        # This team's queue is full: hold nothing more for review. An
        # escalation is still refused, as a plain block.
        review_cap_reached = True
        review_reason = None
        if action == DefenseAction.ESCALATE_TO_HUMAN:
            outcome = DefenseAction.BLOCK
    # Taken before any stripping: the reviewer judges what the client sent
    # (post-PII-redaction), not what was left of it.
    excerpt = build_excerpt(ctx.body) if review_reason else None

    removed_spans = 0
    residual_blocked = False
    if action == DefenseAction.REDACT_AND_ALLOW:
        stripped = await _strip(ctx.body, get_threat_classifier())
        removed_spans = stripped.removed_spans
        if stripped.residual_score >= settings.BANDIT_REDACT_WINDOW_THRESHOLD:
            # What's left after cutting still looks like an attack.
            residual_blocked = True
            outcome = DefenseAction.BLOCK
            result = StageResult.block(BLOCK_REASON)
        else:
            result = StageResult.modify(stripped.body)
    elif action == DefenseAction.BLOCK or outcome == DefenseAction.BLOCK:
        result = StageResult.block(BLOCK_REASON)
    elif action == DefenseAction.ESCALATE_TO_HUMAN:
        result = StageResult.block(ESCALATE_REASON)
    else:
        result = StageResult.allow()

    event = ThreatEvent(
        request_id=uuid.UUID(str(request_id)),
        team_id=ctx.team_id,
        api_key_id=ctx.api_key_id,
        threat_score=dict(threat_score),
        context_features=features_to_dict(x),
        feature_version=FEATURE_VERSION,
        arm_scores=selection.arms_as_dict(),
        action_taken=action,
        outcome=outcome,
        bandit_confidence=selection.confidence,
        escalation_bias=bias,
        session_id=session_id,
        forced_escalation=forced_escalation,
        created_at=now,
    )
    db.add(event)
    await db.flush()
    review_item = await enqueue(db, event, review_reason, excerpt) if review_reason else None
    await db.commit()

    ctx.metadata["defense"] = {
        "action": action.value,
        "outcome": (outcome or action).value,
        "threat_event_id": event.id,
        "confidence": selection.confidence,
        "escalation_bias": bias,
        "forced_escalation": forced_escalation,
        "masked": sorted(a.value for a in masked),
        "removed_spans": removed_spans,
        "residual_blocked": residual_blocked,
        "review_cap_reached": review_cap_reached,
        "review_item_id": review_item.id if review_item else None,
    }
    return result
