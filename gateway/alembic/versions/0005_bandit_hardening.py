"""module 6a hardening: reversible rewards, review amendments, bandit state reset

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-10

- threat_events.outcome: what happened to the request when it differs
  from the bandit's chosen action (see the model's comment).
- threat_events.reward_weight / reward_step: what LinUCB.revert needs to
  withdraw a reward (amended verdicts, human verdicts replacing an
  output-scan label).
- review_queue_items.amendments: earlier verdicts of an amended item.
- bandit_state is emptied. Feature layout v2 (app/core/defense/features.py)
  and state format 2 (bandit.py) can't load a v1 row - LinUCB.from_state
  would raise on every request, and the gateway fails closed, so every
  request would be refused. With no row the store serves the warm-start
  prior until the next labelled decision. Earlier threat_events keep their
  labels; they are never learned from again (feature_version 1).
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("threat_events", sa.Column("outcome", sa.String(length=20), nullable=True))
    op.add_column("threat_events", sa.Column("reward_weight", sa.Float(), nullable=True))
    op.add_column("threat_events", sa.Column("reward_step", sa.Integer(), nullable=True))
    op.add_column(
        "review_queue_items",
        sa.Column(
            "amendments",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.execute("DELETE FROM bandit_state")


def downgrade() -> None:
    # Format-2 state can't be read by the 0004-era code either.
    op.execute("DELETE FROM bandit_state")
    # Values the 0004-era enums don't know: expired items become pending
    # again, output-scan items count as spot checks.
    op.execute("UPDATE review_queue_items SET status = 'pending' WHERE status = 'expired'")
    op.execute("UPDATE review_queue_items SET reason = 'spot_check' WHERE reason = 'output_scan'")
    op.drop_column("review_queue_items", "amendments")
    op.drop_column("threat_events", "reward_step")
    op.drop_column("threat_events", "reward_weight")
    op.drop_column("threat_events", "outcome")
