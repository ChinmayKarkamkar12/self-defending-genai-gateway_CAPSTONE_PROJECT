"""Session guard stage (module 6b): first in PRE_CALL_STAGES. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2, §5.

  1. If the session agent locked this API key out, refuse the request -
     before budget accounting or the classifier spend anything on it.
  2. Otherwise resolve the request's session (app/core/defense/session.py)
     and set `ctx.metadata["session_id"]`, which module 6a's stage uses to
     read the session's escalation_bias and challenge flag.
"""
import time

from redis.asyncio import Redis

from app.core.context import RequestContext, StageResult
from app.core.defense.session import is_locked, resolve_session

LOCKED_REASON = "session locked by the adaptive defense policy pending review"


async def session_guard_stage(ctx: RequestContext) -> StageResult:
    redis: Redis = ctx.metadata["redis"]
    if await is_locked(redis, ctx.api_key_id):
        ctx.metadata["session_locked"] = True
        return StageResult.block(LOCKED_REASON)
    session_id, is_new = await resolve_session(redis, ctx.api_key_id, time.time())
    ctx.metadata["session_id"] = session_id
    ctx.metadata["session_is_new"] = is_new
    return StageResult.allow()
