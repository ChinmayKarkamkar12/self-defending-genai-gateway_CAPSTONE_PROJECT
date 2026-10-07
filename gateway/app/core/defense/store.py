"""Persistence for the bandit's learned parameters. See
project_plan/06a-adaptive-defense-bandit.md §7 task 3.

Postgres (the `bandit_state` table) is the source of truth. Each gateway
process caches the parameters in memory and checks the row's `version` on
every request (one indexed primary-key read), reloading only when another
process - or a review decision in this one - has changed it.

Updates take a row lock (`SELECT ... FOR UPDATE`), apply the update to the
freshly loaded parameters and bump `version`, so concurrent review
decisions in different workers serialise instead of overwriting each
other. The caller commits; if it rolls back instead, the version this
process cached no longer matches the database and the next request reloads.
"""
from typing import Any

import numpy as np
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.defense.bandit import LinUCB, new_bandit
from app.db.models import BanditState, DefenseAction

POLICY_NAME = "default"


class BanditStore:
    def __init__(self) -> None:
        self._cached: LinUCB | None = None
        self._cached_version: int | None = None
        self._prior_state: dict[str, Any] | None = None

    def _prior(self) -> dict[str, Any]:
        # Deterministic, so it's computed once per process and reused.
        if self._prior_state is None:
            self._prior_state = new_bandit().to_state()
        return self._prior_state

    def _load(self, state: dict[str, Any]) -> LinUCB:
        return LinUCB.from_state(state, alpha=settings.BANDIT_ALPHA)

    async def current(self, db: AsyncSession) -> LinUCB:
        """The bandit as of the latest persisted version. Before any
        feedback exists there is no row, and the warm-start prior is used."""
        result = await db.execute(
            select(BanditState.version).where(BanditState.name == POLICY_NAME)
        )
        version = result.scalar_one_or_none()
        if self._cached is not None and self._cached_version == (version or 0):
            self._cached.alpha = settings.BANDIT_ALPHA
            return self._cached

        if version is None:
            bandit = self._load(self._prior())
        else:
            row = await db.get(BanditState, POLICY_NAME, populate_existing=True)
            bandit = self._load(row.params)
        self._cached, self._cached_version = bandit, version or 0
        return bandit

    async def _ensure_row(self, db: AsyncSession) -> None:
        dialect = db.bind.dialect.name
        insert = pg_insert if dialect == "postgresql" else sqlite_insert
        stmt = (
            insert(BanditState)
            .values(name=POLICY_NAME, version=0, params=self._prior())
            .on_conflict_do_nothing(index_elements=["name"])
        )
        await db.execute(stmt)

    async def update(
        self, db: AsyncSession, x: np.ndarray, action: DefenseAction, reward: float
    ) -> int:
        """Apply one reward under a row lock and return the new version.
        Flushes but does not commit - the caller owns the transaction."""
        await self._ensure_row(db)
        result = await db.execute(
            select(BanditState)
            .where(BanditState.name == POLICY_NAME)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        row = result.scalar_one()
        bandit = self._load(row.params)
        bandit.update(x, action, reward)
        row.params = bandit.to_state()
        row.version = row.version + 1
        await db.flush()
        self._cached, self._cached_version = bandit, row.version
        return row.version

    def reset(self) -> None:
        """Test hook: forget the cached parameters."""
        self._cached = None
        self._cached_version = None


bandit_store = BanditStore()
