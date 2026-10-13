"""ORM models. See project_plan/02-gateway-core-proxy.md §2.

Raw API keys are never stored — only a SHA-256 hash (see app/core/auth.py).
"""
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
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


class DefenseAction(StrEnum):
    """The tactical bandit's action space. See project_plan/06a-adaptive-defense-bandit.md §2."""

    ALLOW = "allow"
    REDACT_AND_ALLOW = "redact_and_allow"
    BLOCK = "block"
    ESCALATE_TO_HUMAN = "escalate_to_human"


class ThreatLabel(StrEnum):
    ATTACK = "attack"
    BENIGN = "benign"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    REVIEWED = "reviewed"
    # Not decided within BANDIT_REVIEW_TTL_DAYS; no longer decidable and
    # never learned from. See app/core/defense/review_queue.py.
    EXPIRED = "expired"


class ReviewReason(StrEnum):
    # The bandit chose escalate_to_human; the request was blocked pending review.
    ESCALATION = "escalation"
    # A random sample of an allow/redact/block decision, queued so the arms
    # the bandit didn't escalate still get labelled feedback. The request
    # itself was already handled by the chosen action.
    SPOT_CHECK = "spot_check"
    # An allowed request made the model leak its system prompt. The bandit
    # already learned from that at reduced weight; a human verdict replaces it.
    OUTPUT_SCAN = "output_scan"


class RewardSource(StrEnum):
    HUMAN_REVIEW = "human_review"
    # Post-call evidence: an allowed request's response leaked the system
    # prompt, so the request was an attack. See app/core/defense/feedback.py.
    OUTPUT_SCAN = "output_scan"


class SessionAction(StrEnum):
    """The session agent's action space. See
    project_plan/06b-adaptive-defense-rl-session-agent.md §2 and
    app/core/defense/rl/actions.py for what each one does."""

    MAINTAIN = "maintain"
    TIGHTEN = "tighten"
    RELAX = "relax"
    CHALLENGE = "challenge"
    LOCKOUT = "lockout"


class AuditOutcome(StrEnum):
    """What happened to a request, as one fixed category per audit entry.
    Deliberately an enum and not the free-text block reason / error
    message: those can carry provider or client text, and the audit log
    must never hold anything but fixed values, counts and scores. See
    project_plan/07-audit-logging.md and app/core/audit/entry.py."""

    ALLOWED = "allowed"
    BLOCKED_SESSION_LOCKED = "blocked_session_locked"
    BLOCKED_BUDGET = "blocked_budget"
    BLOCKED_RATE_LIMIT = "blocked_rate_limit"
    BLOCKED_THREAT = "blocked_threat"
    ESCALATED = "escalated"
    BLOCKED_OUTPUT_LEAK = "blocked_output_leak"
    REJECTED_UNKNOWN_MODEL = "rejected_unknown_model"
    UPSTREAM_ERROR = "upstream_error"
    PIPELINE_ERROR = "pipeline_error"
    INTERNAL_ERROR = "internal_error"


# JSONB on Postgres (as the module plan specifies), plain JSON elsewhere so
# the SQLite-backed test suite can create the same tables.
_JSONB = JSON().with_variant(JSONB(), "postgresql")


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


class ThreatEvent(Base):
    """One tactical-bandit decision. See project_plan/06a-adaptive-defense-bandit.md §4.

    Never holds prompt text: only the classifier's probabilities, the
    numeric feature vector the bandit saw, and what it did. The feature
    vector is built from counts and scores (PII is an entity *count*), so
    nothing here can carry a raw PII value.
    """

    __tablename__ = "threat_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    request_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), nullable=False)
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id"), nullable=False)
    threat_score: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False)
    context_features: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False)
    # Bumped whenever app/core/defense/features.py's FEATURE_NAMES changes,
    # so a delayed reward never updates the bandit with a vector built
    # under a different feature layout.
    feature_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Per-arm estimate, uncertainty and adjusted score at decision time -
    # what module 8 plots as the bandit's confidence bounds.
    arm_scores: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False)
    action_taken: Mapped[DefenseAction] = mapped_column(String(20), nullable=False)
    # What actually happened to the request, when that differs from the arm
    # the bandit chose: a redact whose stripped text still scored high was
    # blocked; an escalation past the team's review cap was blocked. The
    # reward is the outcome's, credited to the chosen arm - that is what
    # pulling the arm earned here. NULL = the action was carried out as is.
    outcome: Mapped[DefenseAction | None] = mapped_column(String(20), nullable=True)
    bandit_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    escalation_bias: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    reward_applied: Mapped[float | None] = mapped_column(Float, nullable=True)
    reward_source: Mapped[RewardSource | None] = mapped_column(String(20), nullable=True)
    # Weight the reward was applied with and the chosen arm's update step
    # at that moment - what LinUCB.revert needs to withdraw it later (a
    # human verdict replacing an output-scan label, or an amended verdict).
    reward_weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    reward_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rewarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    human_label: Mapped[ThreatLabel | None] = mapped_column(String(10), nullable=True)
    # Module 6b's session (app/core/defense/session.py); NULL for events
    # recorded before 6b existed.
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # The session agent's `challenge` forced this request to human review,
    # whatever the bandit chose (`arm_scores` still shows what it would
    # have picked). The verdict is still learned from: it is a real label
    # for the escalate arm in this context.
    forced_escalation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )


class SessionPolicyEvent(Base):
    """One run of the session agent (module 6b): what it saw and what it
    did. See project_plan/06b-adaptive-defense-rl-session-agent.md §5.

    Redis holds the live session state and expires it; this table is the
    history the risk-trend endpoint (module 8) and the audit log (module 7)
    read. Like ThreatEvent it holds only numbers - the feature vector is
    built from counts and classifier scores, never from prompt text.
    """

    __tablename__ = "session_policy_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), nullable=False)
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id"), nullable=False)
    # Which policy decided: "rule", "dqn" or "maintain" (SESSION_POLICY).
    policy: Mapped[str] = mapped_column(String(20), nullable=False)
    # What the policy chose, and what was carried out once the guards ran
    # (rl/actions.py: e.g. lockout without any refused request -> maintain).
    proposed_action: Mapped[SessionAction] = mapped_column(String(20), nullable=False)
    action: Mapped[SessionAction] = mapped_column(String(20), nullable=False)
    bias_before: Mapped[float] = mapped_column(Float, nullable=False)
    bias_after: Mapped[float] = mapped_column(Float, nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False)
    feature_version: Mapped[int] = mapped_column(Integer, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )


class ReviewQueueItem(Base):
    """A ThreatEvent waiting for (or given) a human attack/benign verdict.
    See project_plan/06a-adaptive-defense-bandit.md §4.

    `prompt_excerpt` is the conversation text *after* module 4's PII
    redaction - the reviewer needs something to judge, and this is the same
    text that would have gone upstream. Raw PII is never stored here.
    """

    __tablename__ = "review_queue_items"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    threat_event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("threat_events.id"), nullable=False, unique=True
    )
    reason: Mapped[ReviewReason] = mapped_column(String(20), nullable=False)
    status: Mapped[ReviewStatus] = mapped_column(
        String(10), nullable=False, default=ReviewStatus.PENDING, index=True
    )
    prompt_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    reviewer: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decision: Mapped[ThreatLabel | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Earlier verdicts this item had before an amendment, oldest first:
    # [{"decision", "reviewer", "reviewed_at", "amended_by", "amended_at"}].
    amendments: Mapped[list[dict[str, Any]]] = mapped_column(
        _JSONB, nullable=False, default=list
    )

    threat_event: Mapped["ThreatEvent"] = relationship()


class BanditState(Base):
    """Persisted LinUCB parameters, so learning survives restarts. One row
    per named policy (only "default" today). `version` increments on every
    update; each gateway process caches the parameters and reloads them
    when the version it holds is stale. See app/core/defense/store.py.
    """

    __tablename__ = "bandit_state"

    name: Mapped[str] = mapped_column(String(50), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class AuditLogEntry(Base):
    """One hash-chained, append-only audit record per authenticated request.
    See project_plan/07-audit-logging.md §2-3 and docs/adr/0002.

    `entry_hash` = sha256(prev_hash + canonical JSON of every other column),
    and `prev_hash` is the previous entry's `entry_hash` (GENESIS_HASH for
    the first). Rows are never updated or deleted: a Postgres trigger
    (migration 0008) and an ORM guard (app/core/audit/guard.py) both refuse
    it. Holds no prompt text and no raw PII: redaction_summary is entity
    type -> count, threat_score is three probabilities, outcome is an enum.
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    sequence_number: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    request_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("teams.id"), nullable=False, index=True)
    api_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("api_keys.id"), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    http_status: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[AuditOutcome] = mapped_column(String(30), nullable=False)
    # The stage that blocked or failed the request, if one did.
    pipeline_stage: Mapped[str | None] = mapped_column(String(50), nullable=True)
    redaction_summary: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False)
    # Null when the request was stopped before threat detection ran.
    threat_score: Mapped[dict[str, Any] | None] = mapped_column(_JSONB, nullable=True)
    # Module 6a's applied action (ThreatEvent.outcome), "not_evaluated" if
    # the request never reached the bandit.
    action_taken: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    threat_event_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_action: Mapped[str | None] = mapped_column(String(20), nullable=True)
    output_flags: Mapped[dict[str, Any] | None] = mapped_column(_JSONB, nullable=True)
    tokens_in: Mapped[int] = mapped_column(Integer, nullable=False)
    tokens_out: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 6), nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
