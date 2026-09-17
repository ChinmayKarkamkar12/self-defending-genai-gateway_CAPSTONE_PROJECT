"""ORM models. See project_plan/02-gateway-core-proxy.md §2.

Raw API keys are never stored — only a SHA-256 hash (see app/core/auth.py).
"""
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class BudgetPeriod(StrEnum):
    DAILY = "daily"
    MONTHLY = "monthly"


class RedactionMode(StrEnum):
    MASK = "mask"
    TOKENIZE = "tokenize"


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


class RedactionPolicy(Base):
    """Admin-configured PII redaction policy for a team. See
    project_plan/04-pii-redaction.md §2. One active policy per team; a team
    with no policy gets the stage's built-in default (see
    app/core/redaction/policy.py) rather than being left unredacted, since
    PII protection is a security control, not opt-in governance.
    """

    __tablename__ = "redaction_policies"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id"), nullable=False, unique=True
    )
    enabled_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    mode: Mapped[RedactionMode] = mapped_column(String(10), nullable=False)


class RedactionVault(Base):
    """token -> encrypted original value mapping for tokenize-mode redaction.
    See project_plan/04-pii-redaction.md §2. Encrypted at rest with Fernet
    (app/core/redaction/vault.py); no raw value is ever stored in plaintext.
    Schema exists so a future authenticated detokenize endpoint doesn't need
    a migration to add - not wired up until a real use case needs it.

    KNOWN LIMITATION: no retention/expiry. `expires_at` exists as a column
    but nothing currently sets it (`vault.py`'s `store_token` always leaves
    it NULL) or reads/enforces it - there is no cleanup job, cron task, or
    query anywhere that deletes old rows. Every tokenized PII value is kept
    forever once written. This is fine for a capstone demo; a real
    deployment would need a retention job (e.g. delete rows past
    `expires_at`, and actually populate `expires_at` on write) before this
    table could hold real user data at any real scale or duration.
    """

    __tablename__ = "redaction_vault"

    token: Mapped[str] = mapped_column(String(200), primary_key=True)
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Always NULL today - see the KNOWN LIMITATION note above. Column kept so
    # a retention job can be added without a migration, same rationale as
    # the table itself.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
