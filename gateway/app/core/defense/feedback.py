"""Delayed reward: turning a learned label into a bandit update. See
project_plan/06a-adaptive-defense-bandit.md §2, §5 step 5.

Two sources of labels reach `apply_reward`:

- human review (review_queue.py) - escalations and spot checks;
- the post-call output scan (`defense_feedback_stage` below): if a request
  the bandit let through made the model leak its system prompt, the
  request was an attack, with no reviewer needed.

Only the action actually taken is updated, with that action's reward:
the rewards the other actions would have earned weren't observed, which
is what makes this a bandit problem and not supervised learning.

Each ThreatEvent contributes at most one update, whichever label
arrives first. A later label is still recorded (`human_label`) but not
learned from twice.
"""
import logging
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import RequestContext, StageResult
from app.core.defense.features import FEATURE_VERSION, features_from_dict
from app.core.defense.reward import proxy_reward
from app.core.defense.store import bandit_store
from app.db.models import RewardSource, ThreatEvent, ThreatLabel

logger = logging.getLogger("gateway.defense")


async def apply_reward(
    db: AsyncSession, event: ThreatEvent, label: ThreatLabel, source: RewardSource
) -> float | None:
    """Update the bandit with `event`'s reward under `label`. Returns the
    reward applied, or None if nothing was learned (already rewarded, or
    the event was recorded under an older feature layout). Flushes; the
    caller commits."""
    if event.reward_applied is not None:
        return None
    if event.feature_version != FEATURE_VERSION:
        logger.warning(
            "threat event %s has feature version %s (current %s); label kept, no update",
            event.id,
            event.feature_version,
            FEATURE_VERSION,
        )
        return None

    reward = proxy_reward(event.action_taken, label)
    x = features_from_dict(event.context_features)
    await bandit_store.update(db, x, event.action_taken, reward)
    event.reward_applied = reward
    event.reward_source = source
    event.rewarded_at = datetime.now(UTC)
    await db.flush()
    return reward


async def defense_feedback_stage(ctx: RequestContext) -> StageResult:
    """Post-call: a system-prompt leak means the request was an attack.
    No leak proves nothing (most attacks don't target the system prompt),
    so a clean response produces no update. Never blocks - the output scan
    already decided what happens to the response."""
    flags = ctx.metadata.get("output_flags") or {}
    defense = ctx.metadata.get("defense") or {}
    event_id = defense.get("threat_event_id")
    if not flags.get("system_prompt_leaked") or event_id is None:
        return StageResult.allow()

    db: AsyncSession = ctx.metadata["db"]
    event = await db.get(ThreatEvent, event_id)
    if event is None:
        return StageResult.allow()
    await apply_reward(db, event, ThreatLabel.ATTACK, RewardSource.OUTPUT_SCAN)
    await db.commit()
    return StageResult.allow()
