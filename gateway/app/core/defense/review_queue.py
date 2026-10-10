"""Human-review queue for the tactical bandit. See
project_plan/06a-adaptive-defense-bandit.md §2, §5.

Items enter the queue three ways:

- ESCALATION: the bandit chose escalate_to_human. The request was blocked
  and waits here for a verdict.
- SPOT_CHECK: a random BANDIT_SPOT_CHECK_RATE share of the other decisions.
  Without these, only escalated requests would ever be labelled, and
  allow/redact/block would never get feedback from live traffic.
- OUTPUT_SCAN: an allowed request leaked the system prompt (feedback.py).

A reviewer's attack/benign verdict becomes a reward for the action that was
taken (reward.py) and updates the bandit (feedback.apply_reward) - this is
the online-learning loop. The original request is not replayed: a benign
escalation stays blocked, and the client can resend. A wrong verdict can be
corrected with `amend`: the old reward is withdrawn from the bandit, the new
one applied, and the earlier verdict kept in `amendments`.

Flood protection: the queue is the bandit's only source of human labels and
reviewers' time is finite, so one team can hold at most
BANDIT_REVIEW_TEAM_CAP pending items. Past the cap the stage blocks instead
of escalating and stops sampling spot checks for that team. Items pending
longer than BANDIT_REVIEW_TTL_DAYS expire: they are no longer decidable
and never learned from, so a backlog can't feed the bandit stale labels.

The excerpt shown to reviewers is conversation text *after* module 4's PII
redaction - the text that would have gone upstream - capped at
EXCERPT_LIMIT characters. Raw PII is never stored here.
"""
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.core.defense.feedback import apply_reward, revert_reward
from app.core.messages import message_text
from app.db.models import (
    ReviewQueueItem,
    ReviewReason,
    ReviewStatus,
    RewardSource,
    ThreatEvent,
    ThreatLabel,
)

EXCERPT_LIMIT = 4000
TRUNCATION_NOTE = "\n...[truncated]"


class ReviewItemNotFound(Exception):
    pass


class ReviewItemAlreadyDecided(Exception):
    pass


class ReviewItemExpired(Exception):
    pass


class ReviewItemNotDecided(Exception):
    pass


@dataclass(frozen=True)
class DecisionOutcome:
    item: ReviewQueueItem
    reward: float | None
    bandit_updated: bool


def build_excerpt(body: dict[str, Any]) -> str:
    lines = []
    for message in body.get("messages", []):
        if not isinstance(message, dict):
            continue
        text = message_text(message)
        if text:
            lines.append(f"{message.get('role', 'unknown')}: {text}")
    excerpt = "\n".join(lines)
    if len(excerpt) > EXCERPT_LIMIT:
        excerpt = excerpt[: EXCERPT_LIMIT - len(TRUNCATION_NOTE)] + TRUNCATION_NOTE
    return excerpt


async def expire_stale(db: AsyncSession) -> None:
    """Mark pending items older than BANDIT_REVIEW_TTL_DAYS expired.
    Flushes; the caller commits."""
    cutoff = datetime.now(UTC) - timedelta(days=settings.BANDIT_REVIEW_TTL_DAYS)
    await db.execute(
        update(ReviewQueueItem)
        .where(ReviewQueueItem.status == ReviewStatus.PENDING, ReviewQueueItem.created_at < cutoff)
        .values(status=ReviewStatus.EXPIRED)
        .execution_options(synchronize_session=False)
    )


async def pending_for_team(db: AsyncSession, team_id: uuid.UUID) -> int:
    stmt = (
        select(func.count())
        .select_from(ReviewQueueItem)
        .join(ThreatEvent, ReviewQueueItem.threat_event_id == ThreatEvent.id)
        .where(ReviewQueueItem.status == ReviewStatus.PENDING, ThreatEvent.team_id == team_id)
    )
    return int((await db.execute(stmt)).scalar_one())


async def has_capacity(db: AsyncSession, team_id: uuid.UUID) -> bool:
    """Whether `team_id` may add another item (see module docstring)."""
    await expire_stale(db)
    return await pending_for_team(db, team_id) < settings.BANDIT_REVIEW_TEAM_CAP


async def enqueue(
    db: AsyncSession, event: ThreatEvent, reason: ReviewReason, excerpt: str
) -> ReviewQueueItem:
    item = ReviewQueueItem(
        threat_event_id=event.id,
        reason=reason,
        status=ReviewStatus.PENDING,
        prompt_excerpt=excerpt,
        amendments=[],
    )
    db.add(item)
    await db.flush()
    return item


async def list_items(
    db: AsyncSession,
    status: ReviewStatus = ReviewStatus.PENDING,
    limit: int = 50,
    offset: int = 0,
) -> list[ReviewQueueItem]:
    await expire_stale(db)
    stmt = (
        select(ReviewQueueItem)
        .where(ReviewQueueItem.status == status)
        .options(selectinload(ReviewQueueItem.threat_event))
        .order_by(ReviewQueueItem.created_at, ReviewQueueItem.id)
        .limit(limit)
        .offset(offset)
    )
    return list((await db.execute(stmt)).scalars().all())


async def count_pending(db: AsyncSession) -> int:
    await expire_stale(db)
    stmt = select(func.count()).where(ReviewQueueItem.status == ReviewStatus.PENDING)
    return int((await db.execute(stmt)).scalar_one())


async def _locked_item(db: AsyncSession, item_id: uuid.UUID) -> ReviewQueueItem:
    # The row lock means two reviewers acting on the same item can't both
    # apply a reward.
    stmt = (
        select(ReviewQueueItem)
        .where(ReviewQueueItem.id == item_id)
        .options(selectinload(ReviewQueueItem.threat_event))
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    item = (await db.execute(stmt)).scalar_one_or_none()
    if item is None:
        raise ReviewItemNotFound(str(item_id))
    return item


async def decide(
    db: AsyncSession, item_id: uuid.UUID, decision: ThreatLabel, reviewer: str
) -> DecisionOutcome:
    """Record a reviewer's verdict and update the bandit. Commits."""
    await expire_stale(db)
    item = await _locked_item(db, item_id)
    if item.status == ReviewStatus.REVIEWED:
        raise ReviewItemAlreadyDecided(str(item_id))
    if item.status == ReviewStatus.EXPIRED:
        raise ReviewItemExpired(str(item_id))

    event = item.threat_event
    reward = await apply_reward(db, event, decision, RewardSource.HUMAN_REVIEW)
    event.human_label = decision
    item.status = ReviewStatus.REVIEWED
    item.decision = decision
    item.reviewer = reviewer
    item.reviewed_at = datetime.now(UTC)
    await db.commit()
    return DecisionOutcome(item=item, reward=reward, bandit_updated=reward is not None)


async def amend(
    db: AsyncSession, item_id: uuid.UUID, decision: ThreatLabel, reviewer: str
) -> DecisionOutcome:
    """Replace a decided item's verdict: withdraw the reward the old one
    applied, apply the new one, and keep the old verdict in `amendments`.
    Commits."""
    item = await _locked_item(db, item_id)
    if item.status != ReviewStatus.REVIEWED:
        raise ReviewItemNotDecided(str(item_id))

    event = item.threat_event
    reward = None
    if decision != item.decision:
        if event.reward_source == RewardSource.HUMAN_REVIEW:
            await revert_reward(db, event)
        reward = await apply_reward(db, event, decision, RewardSource.HUMAN_REVIEW)
    now = datetime.now(UTC)
    item.amendments = [
        *item.amendments,
        {
            "decision": item.decision,
            "reviewer": item.reviewer,
            "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else None,
            "amended_by": reviewer,
            "amended_at": now.isoformat(),
        },
    ]
    event.human_label = decision
    item.decision = decision
    item.reviewer = reviewer
    item.reviewed_at = now
    await db.commit()
    return DecisionOutcome(item=item, reward=reward, bandit_updated=reward is not None)
