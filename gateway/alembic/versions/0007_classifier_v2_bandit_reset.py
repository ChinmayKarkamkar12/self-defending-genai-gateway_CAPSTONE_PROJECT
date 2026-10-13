"""data expansion: classifier v2 ships, bandit state reset

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-13

- bandit_state is emptied. The learned part of the bandit was fitted to the
  v1 classifier's attack scores; v2 (calibrated, T = 2.24) puts the same
  prompts at different scores, so v1-era updates would pull decisions in the
  wrong places. With no row the store serves the warm-start prior (defined
  on the attack score itself, see reward.py) until the next labelled
  decision. Earlier threat_events keep their scores and labels as history.
  Schema is unchanged.
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DELETE FROM bandit_state")


def downgrade() -> None:
    # Going back to v1 means the state learned on v2's scores is wrong too.
    op.execute("DELETE FROM bandit_state")
