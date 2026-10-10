"""The active session policy and its periodic run. See
project_plan/06b-adaptive-defense-rl-session-agent.md §5, §6.

Which policy runs is the SESSION_POLICY setting:

- "auto" (the default): the trained DQN if - and only if - the shipped
  agent passed the go/no-go evaluation; the rule-based fallback otherwise.
  The verdict is the `decision` field of the JSON file next to the weights
  (dqn_policy.json), written by training/evaluate_rl_agent.py. A missing
  or unreadable verdict, a NO-GO, or weights that fail to load all mean
  the rule: falling back to the rule is a defended, tested policy, not a
  fail-open. Nothing is decided from live traffic - there are no live
  labels to judge an agent by.
- "rule": the rule-based fallback, always.
- "dqn": the trained agent, always. Missing or broken weights then fail the
  request closed, like any stage error: the operator asked for the DQN.
- "maintain": track and log the session, never change anything.

All of them implement `decide(snapshot) -> SessionAction`, so swapping them
is a configuration change only; test_session_integration.py checks that.

The policy doesn't run inside module 6a's decision. After the pre-call
stages finish (whether they allowed or blocked the request - a refused
request is the strongest session signal there is),
app/core/stages/session_policy.py:

  1. adds the request's 6a outcome and score to the session (Redis);
  2. if the policy is due (session.record_outcome), asks it for an action,
     applies the guards (rl/actions.py) and carries the action out -
     the bias / challenge / lock then affects the session's *next* request;
  3. records a SessionPolicyEvent row (history for module 7 and 8), with
     the name of the policy that actually decided ("rule" or "dqn" under
     "auto").

If anything fails, the error goes through the pipeline's FAIL_MODE
handling like every other stage (fail-closed by default).
"""
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from app.config import settings
from app.core.defense.rl.dqn import DEFAULT_WEIGHTS_PATH, DQNPolicy
from app.core.defense.rl.fallback_policy import MaintainPolicy, RuleBasedPolicy
from app.core.defense.rl.features import SessionSnapshot
from app.db.models import SessionAction

logger = logging.getLogger("gateway.defense")

GO = "GO"


class SessionPolicy(Protocol):
    name: str

    def decide(self, snapshot: SessionSnapshot) -> SessionAction: ...


def verdict_path(weights_path: Path) -> Path:
    return weights_path.with_suffix(".json")


def read_verdict(weights_path: Path) -> str | None:
    """The go/no-go decision recorded for these weights, or None."""
    try:
        data = json.loads(verdict_path(weights_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    decision = data.get("decision") if isinstance(data, dict) else None
    return decision if isinstance(decision, str) else None


def _auto(weights_path: Path) -> SessionPolicy:
    verdict = read_verdict(weights_path)
    if verdict != GO:
        logger.info("session policy auto: DQN verdict %r, using the rule-based fallback", verdict)
        return RuleBasedPolicy()
    try:
        policy = DQNPolicy.load(weights_path)
    except Exception as exc:  # noqa: BLE001 - any load failure means "use the rule"
        logger.warning(
            "session policy auto: DQN weights failed to load (%s), using the rule-based fallback",
            type(exc).__name__,
        )
        return RuleBasedPolicy()
    logger.info("session policy auto: DQN passed the go/no-go, using it")
    return policy


@lru_cache(maxsize=4)
def _load(name: str, weights_path: str) -> SessionPolicy:
    path = Path(weights_path) if weights_path else DEFAULT_WEIGHTS_PATH
    if name == "auto":
        return _auto(path)
    if name == "rule":
        return RuleBasedPolicy()
    if name == "maintain":
        return MaintainPolicy()
    if name == "dqn":
        return DQNPolicy.load(path)
    raise ValueError(f"unknown session policy {name!r}")


def get_session_policy() -> SessionPolicy:
    return _load(settings.SESSION_POLICY, settings.SESSION_DQN_WEIGHTS)


def reset_session_policy_cache() -> None:
    _load.cache_clear()
