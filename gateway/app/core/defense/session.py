"""Session identity and live session state for module 6b. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2, §5.

**What a session is.** All requests from one API key until it goes
SESSION_IDLE_SECONDS (default 30 minutes) without one. The gateway sees
API keys, not application users, so this is the closest honest proxy: an
application that shares one key across its users is one session for all of
them (LIMITATIONS.md L6b-1). Session IDs are random (uuid4 hex), not
derived from the key, and are never returned to clients.

The pointer `defense:apikey:{api_key_id}:session` holds
"<session_id>|<last request time>"; a Lua script reads and refreshes it
atomically, so concurrent requests can't open two sessions. The idle check
uses the timestamp passed in, not Redis key expiry, which keeps it
deterministic to test; the key's TTL only garbage-collects it.

**Live state** (all keys expire SESSION_STATE_TTL_FACTOR x idle after the
last request):

- `defense:session:{id}:stats` hash - request count, module 6a outcome
  counts, trailing run of refused requests, PII request count, start time,
  last policy run;
- `defense:session:{id}:scores` list - attack probabilities of the last
  RECENT_WINDOW requests;
- `defense:session:{id}:escalation_bias` and `...:challenge` - the two keys
  module 6a reads (app/core/defense/escalation.py).

**Lock.** `lockout` sets `defense:apikey:{api_key_id}:lock` for
SESSION_LOCK_SECONDS. It is per key (a session *is* a key), time-limited,
and never revokes the key itself; an admin can lift it early.

Nothing here holds prompt text - only counts, scores and IDs.
"""
import time
import uuid
from uuid import UUID

from redis.asyncio import Redis

from app.config import settings
from app.core.defense.escalation import (
    challenge_pending,
    read_escalation_bias,
    set_challenge,
    write_escalation_bias,
)
from app.core.defense.rl.actions import next_bias
from app.core.defense.rl.features import RECENT_WINDOW, SessionSnapshot
from app.db.models import DefenseAction, SessionAction

SESSION_STATE_TTL_FACTOR = 2

_RESOLVE_SCRIPT = """
local cur = redis.call('GET', KEYS[1])
if cur then
  local sep = string.find(cur, '|', 1, true)
  if sep then
    local sid = string.sub(cur, 1, sep - 1)
    local last = tonumber(string.sub(cur, sep + 1))
    if last and tonumber(ARGV[1]) - last <= tonumber(ARGV[2]) then
      redis.call('SET', KEYS[1], sid .. '|' .. ARGV[1], 'EX', ARGV[3])
      return {sid, 0}
    end
  end
end
redis.call('SET', KEYS[1], ARGV[4] .. '|' .. ARGV[1], 'EX', ARGV[3])
return {ARGV[4], 1}
"""


def _text(value: str | bytes | None) -> str | None:
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def session_pointer_key(api_key_id: UUID | str) -> str:
    return f"defense:apikey:{api_key_id}:session"


def lock_key(api_key_id: UUID | str) -> str:
    return f"defense:apikey:{api_key_id}:lock"


def stats_key(session_id: str) -> str:
    return f"defense:session:{session_id}:stats"


def scores_key(session_id: str) -> str:
    return f"defense:session:{session_id}:scores"


def state_ttl() -> int:
    return settings.SESSION_IDLE_SECONDS * SESSION_STATE_TTL_FACTOR


async def resolve_session(
    redis: Redis, api_key_id: UUID | str, now: float | None = None
) -> tuple[str, bool]:
    """(session_id, is_new) for a request from `api_key_id` at `now`."""
    now = time.time() if now is None else now
    candidate = uuid.uuid4().hex
    session_id, is_new = await redis.eval(
        _RESOLVE_SCRIPT,
        1,
        session_pointer_key(api_key_id),
        repr(float(now)),
        str(settings.SESSION_IDLE_SECONDS),
        str(state_ttl()),
        candidate,
    )
    return _text(session_id), bool(int(is_new))


async def current_session(redis: Redis, api_key_id: UUID | str) -> str | None:
    raw = _text(await redis.get(session_pointer_key(api_key_id)))
    return raw.split("|", 1)[0] if raw else None


async def is_locked(redis: Redis, api_key_id: UUID | str) -> bool:
    return bool(await redis.exists(lock_key(api_key_id)))


async def unlock(redis: Redis, api_key_id: UUID | str) -> bool:
    """Lift a lockout and end the key's session, so its next request starts
    a fresh one (an admin who unlocks has judged the old one benign).
    True if a lock was in place."""
    removed = await redis.delete(lock_key(api_key_id))
    await redis.delete(session_pointer_key(api_key_id))
    return bool(removed)


async def read_snapshot(redis: Redis, session_id: str) -> SessionSnapshot:
    stats = {_text(k): _text(v) for k, v in (await redis.hgetall(stats_key(session_id))).items()}
    scores = [float(_text(s)) for s in await redis.lrange(scores_key(session_id), 0, -1)]
    outcome_counts = {
        action.value: int(stats.get(f"count:{action.value}", 0)) for action in DefenseAction
    }
    return SessionSnapshot(
        request_count=int(stats.get("n", 0)),
        outcome_counts=outcome_counts,
        consecutive_refused=int(stats.get("consecutive_refused", 0)),
        recent_scores=tuple(scores),
        pii_requests=int(stats.get("pii_requests", 0)),
        escalation_bias=await read_escalation_bias(redis, session_id),
        challenge_pending=await challenge_pending(redis, session_id),
    )


async def record_outcome(
    redis: Redis,
    session_id: str,
    outcome: DefenseAction,
    p_attack: float,
    had_pii: bool,
    now: float | None = None,
) -> tuple[SessionSnapshot, bool]:
    """Add one request's module 6a outcome to the session. Returns the
    updated snapshot and whether the session policy is due to run (every
    SESSION_POLICY_EVERY_N requests, or SESSION_POLICY_EVERY_SECONDS after
    its last run)."""
    now = time.time() if now is None else now
    key = stats_key(session_id)
    ttl = state_ttl()
    async with redis.pipeline(transaction=True) as pipe:
        pipe.hsetnx(key, "started_at", repr(now))
        pipe.hincrby(key, "n", 1)
        pipe.hincrby(key, f"count:{outcome.value}", 1)
        if outcome == DefenseAction.ALLOW:
            pipe.hset(key, "consecutive_refused", 0)
        else:
            pipe.hincrby(key, "consecutive_refused", 1)
        if had_pii:
            pipe.hincrby(key, "pii_requests", 1)
        pipe.hset(key, "last_at", repr(now))
        pipe.rpush(scores_key(session_id), repr(float(p_attack)))
        pipe.ltrim(scores_key(session_id), -RECENT_WINDOW, -1)
        pipe.expire(key, ttl)
        pipe.expire(scores_key(session_id), ttl)
        await pipe.execute()

    snapshot = await read_snapshot(redis, session_id)
    last_run = _text(await redis.hget(key, "last_policy_at"))
    due = snapshot.request_count % settings.SESSION_POLICY_EVERY_N == 0 or (
        last_run is not None and now - float(last_run) >= settings.SESSION_POLICY_EVERY_SECONDS
    )
    if due:
        await redis.hset(key, "last_policy_at", repr(now))
    return snapshot, due


async def apply_action(
    redis: Redis,
    session_id: str,
    api_key_id: UUID | str,
    action: SessionAction,
    bias_before: float,
) -> float:
    """Carry out a (guarded) session action. Returns the bias afterwards."""
    ttl = state_ttl()
    if action in (SessionAction.TIGHTEN, SessionAction.RELAX):
        return await write_escalation_bias(redis, session_id, next_bias(bias_before, action), ttl)
    if action == SessionAction.CHALLENGE:
        await set_challenge(redis, session_id, ttl)
    elif action == SessionAction.LOCKOUT:
        await redis.set(lock_key(api_key_id), session_id, ex=settings.SESSION_LOCK_SECONDS)
    return bias_before
