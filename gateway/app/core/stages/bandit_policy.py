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
  3. Ask the bandit for an action, exploration included, with `allow`
     masked off above BANDIT_ALLOW_MASK_THRESHOLD.
  4. Record a ThreatEvent; queue a ReviewQueueItem for escalations and for
     a random spot-check sample of the other decisions.
  5. Map the action to a StageResult:
       allow            -> ALLOW
       redact_and_allow -> MODIFY (flagged windows cut, see strip.py)
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
from app.core.defense.escalation import read_escalation_bias
from app.core.defense.features import (
    FEATURE_VERSION,
    FeatureInputs,
    attack_probability,
    build_features,
    features_to_dict,
)
from app.core.defense.review_queue import build_excerpt, enqueue
from app.core.defense.store import bandit_store
from app.core.defense.strip import strip_flagged_content
from app.core.threat.classifier import get_threat_classifier
from app.db.models import DefenseAction, ReviewReason, ThreatEvent

logger = logging.getLogger("gateway.defense")

BLOCK_REASON = "request blocked by the adaptive defense policy"
ESCALATE_REASON = "request held for human review by the adaptive defense policy"
TEAM_RATE_WINDOW_SECONDS = 60

# Module-level so tests can seed it; only decides spot-check sampling.
spot_check_rng = random.Random()


class DefenseError(Exception):
    """Carries only the original exception's type name - see the
    threat stage's ThreatDetectionError for why."""

    def __init__(self, original_type: str):
        super().__init__(f"adaptive defense redaction failed ({original_type})")


async def record_team_request(redis: Redis, team_id: uuid.UUID, now: datetime) -> int:
    """Count this request toward its team's per-minute total and return
    the total so far this minute (including this request)."""
    minute = int(now.timestamp()) // TEAM_RATE_WINDOW_SECONDS
    key = f"defense:rate:{team_id}:{minute}"
    pipe = redis.pipeline()
    pipe.incr(key)
    pipe.expire(key, TEAM_RATE_WINDOW_SECONDS * 2)
    count, _ = await pipe.execute()
    return int(count)


async def _strip(body: dict, classifier) -> tuple[dict, int]:
    failure_type: str | None = None
    try:
        result = await asyncio.to_thread(
            strip_flagged_content, body, classifier, settings.BANDIT_REDACT_WINDOW_THRESHOLD
        )
    except Exception as exc:  # noqa: BLE001 - see DefenseError
        failure_type = type(exc).__name__
    # Raised outside the `except` block so the original exception isn't
    # attached as __context__ - see app/config.py's _load_settings.
    if failure_type is not None:
        logger.error("redact_and_allow failed (%s)", failure_type)
        raise DefenseError(failure_type)
    return result.body, result.removed_spans


async def bandit_policy_stage(ctx: RequestContext) -> StageResult:
    db = ctx.metadata["db"]
    redis: Redis = ctx.metadata["redis"]
    # No score means module 5 didn't run - a wiring bug. KeyError fails
    # the request closed rather than deciding blind.
    threat_score = ctx.metadata["threat_score"]
    scan = ctx.metadata.get("threat_scan") or {}
    request_id = ctx.metadata.setdefault("request_id", str(uuid.uuid4()))
    now = datetime.now(UTC)

    team_requests = await record_team_request(redis, ctx.team_id, now)
    inputs = FeatureInputs(
        threat_score=threat_score,
        system_prompt_threat_score=ctx.metadata.get("system_prompt_threat_score"),
        scan_windows=int(scan.get("windows", 1)),
        scan_truncated=bool(scan.get("truncated", False)),
        pii_entity_count=sum((ctx.metadata.get("redaction_map") or {}).values()),
        hour_utc=now.hour + now.minute / 60.0,
        team_requests_this_minute=team_requests,
    )
    x = build_features(inputs)
    bias = await read_escalation_bias(redis, ctx.metadata.get("session_id"))

    masked = safety_mask(
        attack_probability(threat_score), settings.BANDIT_ALLOW_MASK_THRESHOLD
    )

    bandit = await bandit_store.current(db)
    selection = bandit.select(
        x, alpha=settings.BANDIT_ALPHA, escalation_bias=bias, masked=masked
    )
    action = selection.action

    review_reason: ReviewReason | None = None
    if action == DefenseAction.ESCALATE_TO_HUMAN:
        review_reason = ReviewReason.ESCALATION
    elif spot_check_rng.random() < settings.BANDIT_SPOT_CHECK_RATE:
        review_reason = ReviewReason.SPOT_CHECK
    # Taken before any stripping: the reviewer judges what the client sent
    # (post-PII-redaction), not what was left of it.
    excerpt = build_excerpt(ctx.body) if review_reason else None

    removed_spans = 0
    if action == DefenseAction.REDACT_AND_ALLOW:
        new_body, removed_spans = await _strip(ctx.body, get_threat_classifier())
        result = StageResult.modify(new_body)
    elif action == DefenseAction.BLOCK:
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
        bandit_confidence=selection.confidence,
        escalation_bias=bias,
        created_at=now,
    )
    db.add(event)
    await db.flush()
    review_item = await enqueue(db, event, review_reason, excerpt) if review_reason else None
    await db.commit()

    ctx.metadata["defense"] = {
        "action": action.value,
        "threat_event_id": event.id,
        "confidence": selection.confidence,
        "escalation_bias": bias,
        "masked": sorted(a.value for a in masked),
        "removed_spans": removed_spans,
        "review_item_id": review_item.id if review_item else None,
    }
    return result
