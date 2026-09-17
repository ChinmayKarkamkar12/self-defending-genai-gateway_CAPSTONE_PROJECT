"""redaction_policies and redaction_vault tables

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-17

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "redaction_policies",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("enabled_entities", sa.JSON(), nullable=False),
        sa.Column("mode", sa.String(length=10), nullable=False),
    )
    op.create_index(
        "ix_redaction_policies_team_id", "redaction_policies", ["team_id"], unique=True
    )

    op.create_table(
        "redaction_vault",
        sa.Column("token", sa.String(length=200), primary_key=True),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_redaction_vault_team_id", "redaction_vault", ["team_id"])


def downgrade() -> None:
    op.drop_index("ix_redaction_vault_team_id", table_name="redaction_vault")
    op.drop_table("redaction_vault")
    op.drop_index("ix_redaction_policies_team_id", table_name="redaction_policies")
    op.drop_table("redaction_policies")
