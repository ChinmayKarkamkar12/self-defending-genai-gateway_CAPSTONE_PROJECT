"""module 7: tamper-evident audit log

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-13

- audit_log_entries: one hash-chained row per authenticated request. See
  project_plan/07-audit-logging.md and docs/adr/0002-audit-log-immutability.md.
- A trigger rejects every UPDATE, DELETE and TRUNCATE on the table, for any
  role that doesn't explicitly disable it. The hash chain is what catches a
  privileged user who does (scripts/tamper_demo.py shows exactly that).
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Uuid(), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("api_key_id", sa.Uuid(), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=30), nullable=False),
        sa.Column("pipeline_stage", sa.String(length=50), nullable=True),
        sa.Column("redaction_summary", postgresql.JSONB(), nullable=False),
        sa.Column("threat_score", postgresql.JSONB(), nullable=True),
        sa.Column("action_taken", sa.String(length=30), nullable=False),
        sa.Column("threat_event_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("session_action", sa.String(length=20), nullable=True),
        sa.Column("output_flags", postgresql.JSONB(), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(10, 6), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False, unique=True),
    )
    op.create_index("ix_audit_log_entries_timestamp", "audit_log_entries", ["timestamp"])
    op.create_index("ix_audit_log_entries_request_id", "audit_log_entries", ["request_id"])
    op.create_index("ix_audit_log_entries_team_id", "audit_log_entries", ["team_id"])
    op.create_index("ix_audit_log_entries_action_taken", "audit_log_entries", ["action_taken"])

    op.execute(
        """
        CREATE FUNCTION audit_log_entries_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log_entries is append-only (% rejected)', TG_OP;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_entries_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_log_entries
        FOR EACH ROW EXECUTE FUNCTION audit_log_entries_immutable()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_entries_no_truncate
        BEFORE TRUNCATE ON audit_log_entries
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_entries_immutable()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_entries_no_truncate ON audit_log_entries")
    op.execute("DROP TRIGGER IF EXISTS audit_log_entries_no_update_delete ON audit_log_entries")
    op.drop_table("audit_log_entries")
    op.execute("DROP FUNCTION IF EXISTS audit_log_entries_immutable()")
