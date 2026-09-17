"""usage_records and budget_policies tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-17

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "usage_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("api_key_id", sa.Uuid(), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(10, 6), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_usage_records_team_id", "usage_records", ["team_id"])
    op.create_index("ix_usage_records_timestamp", "usage_records", ["timestamp"])

    op.create_table(
        "budget_policies",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("period", sa.String(length=10), nullable=False),
        sa.Column("limit_usd", sa.Numeric(10, 2), nullable=False),
        sa.Column("rate_limit_rps", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_budget_policies_team_id", "budget_policies", ["team_id"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_budget_policies_team_id", table_name="budget_policies")
    op.drop_table("budget_policies")
    op.drop_index("ix_usage_records_timestamp", table_name="usage_records")
    op.drop_index("ix_usage_records_team_id", table_name="usage_records")
    op.drop_table("usage_records")
