"""ORM models. See project_plan/02-gateway-core-proxy.md §2.

Raw API keys are never stored — only a SHA-256 hash (see app/core/auth.py).
"""
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class BudgetPeriod(StrEnum):
    DAILY = "daily"
    MONTHLY = "monthly"


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="team")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    team: Mapped["Team"] = relationship(back_populates="api_keys")


class UsageRecord(Base):
    """Durable, post-call record of one request's actual cost. See
    project_plan/03-cost-usage-governance.md §2. Never stores raw prompt/response
    content or PII — only token counts and derived cost.
    """

    __tablename__ = "usage_records"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id"), nullable=False)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 6), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class BudgetPolicy(Base):
    """Admin-configured spend limit + rate limit for a team. See
    project_plan/03-cost-usage-governance.md §2. One active policy per team.
    """

    __tablename__ = "budget_policies"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id"), nullable=False, unique=True
    )
    period: Mapped[BudgetPeriod] = mapped_column(String(10), nullable=False)
    limit_usd: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, nullable=False)
