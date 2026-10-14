"""module 8: admin users for the dashboard

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-14

- admin_users: dashboard administrators with a salted scrypt password hash
  (app/core/admin_auth.py). Login sessions are kept in Redis, so there is no
  sessions table. Every /v1/admin route now requires a logged-in admin.
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_table("admin_users")
