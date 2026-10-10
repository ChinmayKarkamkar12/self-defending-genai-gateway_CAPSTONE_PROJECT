"""Session policy step (module 6b). See app/core/defense/rl/policy.py for
what it does and why it runs after the pre-call stages, allowed or not.

Never blocks the request it runs after; what it decides applies to the
session's next request. Skipped when module 6a didn't decide the request
(a budget refusal, a locked key, a stage failure): there is no outcome to
record.
"""
import time

from redis.asyncio import Redis

from app.core.context import RequestContext, StageResult
from app.core.defense.features import attack_probability
from app.core.defense.rl.actions import guard
from app.core.defense.rl.features import (
    SESSION_FEATURE_VERSION,
    build_session_features,
    session_features_to_dict,
)
from app.core.defense.rl.policy import get_session_policy
from app.core.defense.session import apply_action, record_outcome
from app.db.models import DefenseAction, SessionPolicyEvent


async def session_policy_stage(ctx: RequestContext) -> StageResult:
    defense = ctx.metadata.get("defense")
    session_id = ctx.metadata.get("session_id")
    if not defense or not session_id:
        return StageResult.allow()
    redis: Redis = ctx.metadata["redis"]
    db = ctx.metadata["db"]

    now = time.time()
    snapshot, due = await record_outcome(
        redis,
        session_id,
        DefenseAction(defense["outcome"]),
        attack_probability(ctx.metadata["threat_score"]),
        sum((ctx.metadata.get("redaction_map") or {}).values()) > 0,
        now,
    )
    if not due:
        return StageResult.allow()

    policy = get_session_policy()
    proposed = policy.decide(snapshot)
    action = guard(proposed, snapshot)
    bias_after = await apply_action(
        redis, session_id, ctx.api_key_id, action, snapshot.escalation_bias
    )
    db.add(
        SessionPolicyEvent(
            session_id=session_id,
            team_id=ctx.team_id,
            api_key_id=ctx.api_key_id,
            policy=policy.name,
            proposed_action=proposed,
            action=action,
            bias_before=snapshot.escalation_bias,
            bias_after=bias_after,
            features=session_features_to_dict(build_session_features(snapshot)),
            feature_version=SESSION_FEATURE_VERSION,
            request_count=snapshot.request_count,
        )
    )
    await db.commit()
    ctx.metadata["session_policy"] = {
        "policy": policy.name,
        "proposed_action": proposed.value,
        "action": action.value,
        "bias_before": snapshot.escalation_bias,
        "bias_after": bias_after,
    }
    return StageResult.allow()
