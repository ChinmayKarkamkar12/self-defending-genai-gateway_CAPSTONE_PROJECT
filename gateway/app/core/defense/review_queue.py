"""Human-review queue for the tactical bandit. See
project_plan/06a-adaptive-defense-bandit.md §2, §5.

Items enter the queue two ways:

- ESCALATION: the bandit chose escalate_to_human. The request was blocked
  and waits here for a verdict.
- SPOT_CHECK: a random BANDIT_SPOT_CHECK_RATE share of the other decisions.
  Without these, only escalated requests would ever be labelled, and
  allow/redact/block would never get feedback from live traffic.

A reviewer's attack/benign verdict becomes a reward for the action that was
taken (reward.py) and updates the bandit (feedback.apply_reward) - this is
the online-learning loop. The original request is not replayed: a benign
escalation stays blocked, and the client can resend.

The excerpt shown to reviewers is conversation text *after* module 4's PII
redaction - the text that would have gone upstream - capped at
EXCERPT_LIMIT characters. Raw PII is never stored here.
"""
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.defense.feedback import apply_reward
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


async def enqueue(
    db: AsyncSession, event: ThreatEvent, reason: ReviewReason, excerpt: str
) -> ReviewQueueItem:
    item = ReviewQueueItem(
        threat_event_id=event.id,
        reason=reason,
        status=ReviewStatus.PENDING,
        prompt_excerpt=excerpt,
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
    stmt = select(func.count()).where(ReviewQueueItem.status == ReviewStatus.PENDING)
    return int((await db.execute(stmt)).scalar_one())


async def decide(
    db: AsyncSession, item_id: uuid.UUID, decision: ThreatLabel, reviewer: str
) -> DecisionOutcome:
    """Record a reviewer's verdict and update the bandit. The item row is
    locked so two reviewers deciding the same item can't both apply a
    reward. Commits."""
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
    if item.status == ReviewStatus.REVIEWED:
        raise ReviewItemAlreadyDecided(str(item_id))

    event = item.threat_event
    reward = await apply_reward(db, event, decision, RewardSource.HUMAN_REVIEW)
    event.human_label = decision
    item.status = ReviewStatus.REVIEWED
    item.decision = decision
    item.reviewer = reviewer
    item.reviewed_at = datetime.now(UTC)
    await db.commit()
    return DecisionOutcome(item=item, reward=reward, bandit_updated=reward is not None)
