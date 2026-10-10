"""The `escalation_bias` hook - the only contract between module 6a and
module 6b. See project_plan/06a-adaptive-defense-bandit.md §3 and
project_plan/06b-adaptive-defense-rl-session-agent.md §5.

Module 6b's session agent writes a float in [-0.3, 1] to a per-session Redis
key; module 6a's bandit stage reads it before choosing an action. The flow
is one-way: 6a never reads 6b's internal state and 6b never picks 6a's
action, it only nudges this value. Positive = stricter, negative = more
permissive (see bandit.BIAS_DIRECTION, and bandit.py's module docstring
for why the negative side is capped at -0.3).

6a only reads. Which session a request belongs to is 6b's decision; until
6b sets `ctx.metadata["session_id"]`, every request gets the neutral 0.0.
"""
import logging
import math

from redis.asyncio import Redis

from app.core.defense.bandit import clamp_bias

logger = logging.getLogger("gateway.defense")

NEUTRAL_BIAS = 0.0


def escalation_bias_key(session_id: str) -> str:
    return f"defense:session:{session_id}:escalation_bias"


def parse_bias(raw: str | bytes | None) -> float:
    """Neutral if missing or malformed; clamped to [MIN_BIAS, MAX_BIAS]
    = [-0.3, 1] otherwise. A
    garbage value falls back to neutral rather than failing the request:
    the bias only tunes an otherwise complete policy."""
    if raw is None:
        return NEUTRAL_BIAS
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning("ignoring malformed escalation_bias value")
        return NEUTRAL_BIAS
    if not math.isfinite(value):
        logger.warning("ignoring non-finite escalation_bias value")
        return NEUTRAL_BIAS
    return clamp_bias(value)


async def read_escalation_bias(redis: Redis, session_id: str | None) -> float:
    if not session_id:
        return NEUTRAL_BIAS
    return parse_bias(await redis.get(escalation_bias_key(session_id)))
