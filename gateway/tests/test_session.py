"""Session identity and Redis session state. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2, §8."""
import asyncio
import uuid

import pytest

from app.config import settings
from app.core.defense.escalation import (
    challenge_pending,
    read_escalation_bias,
    take_challenge,
)
from app.core.defense.session import (
    apply_action,
    is_locked,
    lock_key,
    record_outcome,
    resolve_session,
    unlock,
)
from app.db.models import DefenseAction, SessionAction

KEY = uuid.uuid4()


@pytest.fixture(autouse=True)
def idle_window(monkeypatch):
    monkeypatch.setattr(settings, "SESSION_IDLE_SECONDS", 1800)


async def test_session_id_stable_within_window(fake_redis):
    first, is_new = await resolve_session(fake_redis, KEY, now=1000.0)
    assert is_new
    # Each request refreshes the window: 25 minutes apart, three times.
    for t in (2500.0, 4000.0, 5500.0):
        sid, is_new = await resolve_session(fake_redis, KEY, now=t)
        assert sid == first and not is_new

    later, is_new = await resolve_session(fake_redis, KEY, now=5500.0 + 1801)
    assert is_new and later != first


async def test_sessions_are_per_api_key(fake_redis):
    a, _ = await resolve_session(fake_redis, uuid.uuid4(), now=1.0)
    b, _ = await resolve_session(fake_redis, uuid.uuid4(), now=1.0)
    assert a != b


async def test_concurrent_requests_share_one_new_session(fake_redis):
    results = await asyncio.gather(
        *(resolve_session(fake_redis, KEY, now=50.0) for _ in range(20))
    )
    assert len({sid for sid, _ in results}) == 1
    assert sum(is_new for _, is_new in results) == 1


async def test_session_id_is_not_derived_from_the_key(fake_redis):
    sid, _ = await resolve_session(fake_redis, KEY, now=1.0)
    assert str(KEY) not in sid and KEY.hex not in sid


async def test_record_outcome_tracks_counts_and_runs(fake_redis):
    sid = "s-record"
    outcomes = [DefenseAction.ALLOW, DefenseAction.BLOCK, DefenseAction.ESCALATE_TO_HUMAN]
    for i, outcome in enumerate(outcomes):
        snapshot, due = await record_outcome(fake_redis, sid, outcome, 0.1 * i, i == 0, now=i)
        assert due  # SESSION_POLICY_EVERY_N defaults to 1
    assert snapshot.request_count == 3
    assert snapshot.count(DefenseAction.BLOCK) == 1
    assert snapshot.consecutive_refused == 2
    assert snapshot.refused_count == 2
    assert snapshot.pii_requests == 1
    assert list(snapshot.recent_scores) == pytest.approx([0.0, 0.1, 0.2])

    snapshot, _ = await record_outcome(fake_redis, sid, DefenseAction.ALLOW, 0.0, False, now=4)
    assert snapshot.consecutive_refused == 0


async def test_recent_scores_are_a_rolling_window(fake_redis):
    for i in range(25):
        snapshot, _ = await record_outcome(
            fake_redis, "s-roll", DefenseAction.ALLOW, i / 100, False, now=i
        )
    assert len(snapshot.recent_scores) == 10
    assert snapshot.recent_scores[-1] == pytest.approx(0.24)


async def test_policy_trigger_every_n_or_after_t_seconds(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "SESSION_POLICY_EVERY_N", 3)
    monkeypatch.setattr(settings, "SESSION_POLICY_EVERY_SECONDS", 60.0)
    due = []
    for t in (0.0, 1.0, 2.0, 3.0, 100.0):
        _, d = await record_outcome(fake_redis, "s-due", DefenseAction.ALLOW, 0.0, False, now=t)
        due.append(d)
    # 3rd request (count), then the 5th: 97 s after the last run.
    assert due == [False, False, True, False, True]


async def test_actions_write_the_6a_contract_keys(fake_redis):
    sid = "s-act"
    assert await apply_action(fake_redis, sid, KEY, SessionAction.TIGHTEN, 0.0) == 0.25
    assert await read_escalation_bias(fake_redis, sid) == 0.25
    assert await apply_action(fake_redis, sid, KEY, SessionAction.TIGHTEN, 0.9) == 1.0
    assert await apply_action(fake_redis, sid, KEY, SessionAction.RELAX, -0.2) == -0.3
    assert await apply_action(fake_redis, sid, KEY, SessionAction.MAINTAIN, 0.4) == 0.4

    await apply_action(fake_redis, sid, KEY, SessionAction.CHALLENGE, 0.0)
    assert await challenge_pending(fake_redis, sid)
    assert await take_challenge(fake_redis, sid)
    assert not await take_challenge(fake_redis, sid)  # consumed exactly once


async def test_lockout_is_time_limited_and_unlockable(fake_redis, monkeypatch):
    monkeypatch.setattr(settings, "SESSION_LOCK_SECONDS", 900)
    sid, _ = await resolve_session(fake_redis, KEY, now=1.0)
    await apply_action(fake_redis, sid, KEY, SessionAction.LOCKOUT, 0.0)
    assert await is_locked(fake_redis, KEY)
    assert 0 < await fake_redis.ttl(lock_key(KEY)) <= 900

    assert await unlock(fake_redis, KEY)
    assert not await is_locked(fake_redis, KEY)
    # Unlocking ends the session: the next request starts a fresh one.
    new_sid, is_new = await resolve_session(fake_redis, KEY, now=2.0)
    assert is_new and new_sid != sid
    assert not await unlock(fake_redis, KEY)
