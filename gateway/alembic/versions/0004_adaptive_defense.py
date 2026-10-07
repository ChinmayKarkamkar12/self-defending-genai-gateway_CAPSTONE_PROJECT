"""threat_events, review_queue_items and bandit_state tables

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-07

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("api_key_id", sa.Uuid(), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("threat_score", postgresql.JSONB(), nullable=False),
        sa.Column("context_features", postgresql.JSONB(), nullable=False),
        sa.Column("feature_version", sa.Integer(), nullable=False),
        sa.Column("arm_scores", postgresql.JSONB(), nullable=False),
        sa.Column("action_taken", sa.String(length=20), nullable=False),
        sa.Column("bandit_confidence", sa.Float(), nullable=False),
        sa.Column("escalation_bias", sa.Float(), nullable=False),
        sa.Column("reward_applied", sa.Float(), nullable=True),
        sa.Column("reward_source", sa.String(length=20), nullable=True),
        sa.Column("rewarded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("human_label", sa.String(length=10), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_threat_events_request_id", "threat_events", ["request_id"])
    op.create_index("ix_threat_events_created_at", "threat_events", ["created_at"])

    op.create_table(
        "review_queue_items",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "threat_event_id",
            sa.Uuid(),
            sa.ForeignKey("threat_events.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("reason", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("prompt_excerpt", sa.Text(), nullable=False),
        sa.Column("reviewer", sa.String(length=200), nullable=True),
        sa.Column("decision", sa.String(length=10), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_review_queue_items_status", "review_queue_items", ["status"])

    op.create_table(
        "bandit_state",
        sa.Column("name", sa.String(length=50), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("params", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("bandit_state")
    op.drop_index("ix_review_queue_items_status", table_name="review_queue_items")
    op.drop_table("review_queue_items")
    op.drop_index("ix_threat_events_created_at", table_name="threat_events")
    op.drop_index("ix_threat_events_request_id", table_name="threat_events")
    op.drop_table("threat_events")
