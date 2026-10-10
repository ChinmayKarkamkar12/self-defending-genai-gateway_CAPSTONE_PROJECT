"""module 6b: session agent history and session-tagged threat events

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-10

- session_policy_events: one row per run of the session agent - the
  history behind GET /v1/admin/sessions/{id}/risk-trend (Redis only holds
  the live, expiring state).
- threat_events.session_id: which session a bandit decision belonged to.
- threat_events.forced_escalation: the session agent's `challenge` forced
  this request to human review.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("threat_events", sa.Column("session_id", sa.String(length=64), nullable=True))
    op.create_index("ix_threat_events_session_id", "threat_events", ["session_id"])
    op.add_column(
        "threat_events",
        sa.Column(
            "forced_escalation", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )

    op.create_table(
        "session_policy_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("api_key_id", sa.Uuid(), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("policy", sa.String(length=20), nullable=False),
        sa.Column("proposed_action", sa.String(length=20), nullable=False),
        sa.Column("action", sa.String(length=20), nullable=False),
        sa.Column("bias_before", sa.Float(), nullable=False),
        sa.Column("bias_after", sa.Float(), nullable=False),
        sa.Column("features", postgresql.JSONB(), nullable=False),
        sa.Column("feature_version", sa.Integer(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_session_policy_events_session_id", "session_policy_events", ["session_id"]
    )
    op.create_index(
        "ix_session_policy_events_created_at", "session_policy_events", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_session_policy_events_created_at", table_name="session_policy_events")
    op.drop_index("ix_session_policy_events_session_id", table_name="session_policy_events")
    op.drop_table("session_policy_events")
    op.drop_column("threat_events", "forced_escalation")
    op.drop_index("ix_threat_events_session_id", table_name="threat_events")
    op.drop_column("threat_events", "session_id")
