"""The active session policy and its periodic run. See
project_plan/06b-adaptive-defense-rl-session-agent.md §5, §6.

Which policy runs is the SESSION_POLICY setting - "rule" (the fallback),
"dqn" (the trained agent) or "maintain" (track and log, change nothing).
All three implement `decide(snapshot) -> SessionAction`, so swapping them
is a configuration change only; test_session_integration.py checks that.

The policy doesn't run inside module 6a's decision. After the pre-call
stages finish (whether they allowed or blocked the request - a refused
request is the strongest session signal there is),
app/core/stages/session_policy.py:

  1. adds the request's 6a outcome and score to the session (Redis);
  2. if the policy is due (session.record_outcome), asks it for an action,
     applies the guards (rl/actions.py) and carries the action out -
     the bias / challenge / lock then affects the session's *next* request;
  3. records a SessionPolicyEvent row (history for module 7 and 8).

If anything fails, the error goes through the pipeline's FAIL_MODE
handling like every other stage (fail-closed by default).
"""
from functools import lru_cache
from typing import Protocol

from app.config import settings
from app.core.defense.rl.dqn import DEFAULT_WEIGHTS_PATH, DQNPolicy
from app.core.defense.rl.fallback_policy import MaintainPolicy, RuleBasedPolicy
from app.core.defense.rl.features import SessionSnapshot
from app.db.models import SessionAction


class SessionPolicy(Protocol):
    name: str

    def decide(self, snapshot: SessionSnapshot) -> SessionAction: ...


@lru_cache(maxsize=4)
def _load(name: str, weights_path: str) -> SessionPolicy:
    if name == "rule":
        return RuleBasedPolicy()
    if name == "maintain":
        return MaintainPolicy()
    if name == "dqn":
        return DQNPolicy.load(weights_path or DEFAULT_WEIGHTS_PATH)
    raise ValueError(f"unknown session policy {name!r}")


def get_session_policy() -> SessionPolicy:
    return _load(settings.SESSION_POLICY, settings.SESSION_DQN_WEIGHTS)


def reset_session_policy_cache() -> None:
    _load.cache_clear()
