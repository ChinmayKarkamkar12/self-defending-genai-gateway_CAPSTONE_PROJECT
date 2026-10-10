"""Delayed reward: turning a learned label into a bandit update. See
project_plan/06a-adaptive-defense-bandit.md §2, §5 step 5.

Two sources of labels reach `apply_reward`:

- human review (review_queue.py) - escalations, spot checks and output-scan
  hits, weight 1.0;
- the post-call output scan (`defense_feedback_stage` below): if a request
  the bandit let through made the model leak its system prompt, the
  request was an attack, with no reviewer needed.

The output scan is one-sided: it only ever produces *attack* labels, and
only on allowed requests. At full weight, 30 of them on p 0.05-0.2 traffic
moved the bandit to redacting p=0 requests (L6a-10 in LIMITATIONS.md). So
it learns at BANDIT_OUTPUT_SCAN_WEIGHT (0.2) and the request is also queued
for a human, whose verdict then replaces the automatic label.

Only the action actually taken is updated: the rewards the other actions
would have earned weren't observed, which is what makes this a bandit
problem and not supervised learning. The reward is that of what happened
to the request (`ThreatEvent.outcome`, e.g. a redact that ended up
blocked), credited to the arm the bandit pulled.

Each ThreatEvent counts at most once. A human verdict on an event that so
far has only an automatic label withdraws that label first
(`revert_reward`) and applies its own; any other later label is recorded
(`human_label`) but not learned from twice. A reviewer can still correct
their own verdict through review_queue.amend.
"""
import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.context import RequestContext, StageResult
from app.core.defense.bandit import AppliedUpdate
from app.core.defense.features import FEATURE_VERSION, features_from_dict
from app.core.defense.reward import proxy_reward
from app.core.defense.store import bandit_store
from app.db.models import ReviewQueueItem, ReviewReason, RewardSource, ThreatEvent, ThreatLabel

logger = logging.getLogger("gateway.defense")


def _learnable(event: ThreatEvent) -> bool:
    if event.feature_version == FEATURE_VERSION:
        return True
    logger.warning(
        "threat event %s has feature version %s (current %s); label kept, no update",
        event.id,
        event.feature_version,
        FEATURE_VERSION,
    )
    return False


async def revert_reward(db: AsyncSession, event: ThreatEvent) -> bool:
    """Withdraw `event`'s applied reward from the bandit. Returns False if
    there was nothing to withdraw. Flushes; the caller commits."""
    if event.reward_applied is None or not _learnable(event):
        return False
    if event.reward_step is None or event.reward_weight is None:
        # Rewarded before reversal was possible - can't be withdrawn exactly.
        return False
    await bandit_store.revert(
        db,
        features_from_dict(event.context_features),
        event.action_taken,
        event.reward_applied,
        AppliedUpdate(arm_step=event.reward_step, weight=event.reward_weight),
    )
    event.reward_applied = None
    event.reward_source = None
    event.reward_weight = None
    event.reward_step = None
    event.rewarded_at = None
    await db.flush()
    return True


async def apply_reward(
    db: AsyncSession,
    event: ThreatEvent,
    label: ThreatLabel,
    source: RewardSource,
    weight: float = 1.0,
) -> float | None:
    """Update the bandit with `event`'s reward under `label`. Returns the
    reward applied, or None if nothing was learned (already rewarded, or
    the event was recorded under an older feature layout). Flushes; the
    caller commits."""
    if not _learnable(event):
        return None
    if event.reward_applied is not None:
        upgrade = (
            source == RewardSource.HUMAN_REVIEW
            and event.reward_source != RewardSource.HUMAN_REVIEW
        )
        if not (upgrade and await revert_reward(db, event)):
            return None

    reward = proxy_reward(event.outcome or event.action_taken, label)
    x = features_from_dict(event.context_features)
    applied = await bandit_store.update(db, x, event.action_taken, reward, weight)
    event.reward_applied = reward
    event.reward_source = source
    event.reward_weight = applied.weight
    event.reward_step = applied.arm_step
    event.rewarded_at = datetime.now(UTC)
    await db.flush()
    return reward


async def defense_feedback_stage(ctx: RequestContext) -> StageResult:
    """Post-call: a system-prompt leak means the request was an attack.
    No leak proves nothing (most attacks don't target the system prompt),
    so a clean response produces no update. Never blocks - the output scan
    already decided what happens to the response."""
    # Imported here: review_queue imports this module.
    from app.core.defense import review_queue

    flags = ctx.metadata.get("output_flags") or {}
    defense = ctx.metadata.get("defense") or {}
    event_id = defense.get("threat_event_id")
    if not flags.get("system_prompt_leaked") or event_id is None:
        return StageResult.allow()

    db: AsyncSession = ctx.metadata["db"]
    event = await db.get(ThreatEvent, event_id)
    if event is None:
        return StageResult.allow()
    await apply_reward(
        db, event, ThreatLabel.ATTACK, RewardSource.OUTPUT_SCAN, settings.BANDIT_OUTPUT_SCAN_WEIGHT
    )
    already_queued = (
        await db.execute(
            select(ReviewQueueItem.id).where(ReviewQueueItem.threat_event_id == event.id)
        )
    ).scalar_one_or_none()
    if already_queued is None and await review_queue.has_capacity(db, event.team_id):
        await review_queue.enqueue(
            db, event, ReviewReason.OUTPUT_SCAN, review_queue.build_excerpt(ctx.body)
        )
    await db.commit()
    return StageResult.allow()
