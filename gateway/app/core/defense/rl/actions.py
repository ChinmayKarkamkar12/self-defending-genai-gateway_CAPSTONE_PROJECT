"""What each session action does. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2.

| action    | effect                                                          |
|-----------|-----------------------------------------------------------------|
| maintain  | nothing                                                         |
| tighten   | escalation_bias += TIGHTEN_STEP (6a gets stricter)              |
| relax     | escalation_bias -= RELAX_STEP (6a gets more permissive)         |
| challenge | the session's next request goes to human review (6a's           |
|           | escalate_to_human), whatever its own score                      |
| lockout   | the API key's requests are refused for SESSION_LOCK_SECONDS     |

The bias stays inside 6a's clamp, [MIN_BIAS, MAX_BIAS] = [-0.3, 1.0].

What the bias can and can't do (measured on the warm-start bandit, see
PROGRESS.md): +1.0 still allows anything the classifier scores below 0.2,
and only requests scored 0.2-0.9 change decision - about 1% of held-out
traffic. Tightening therefore can't catch an attack the classifier misses
(those score near 0); only `challenge` and `lockout` can, and only because
of what the session did before.

Guards, applied to every policy's choice (rule, DQN, and in the simulator
too, so offline numbers describe what runs):

- `lockout` needs at least LOCKOUT_MIN_REFUSED (2) refused requests in
  the session. Since a session is a whole API key (L6b-1), a wrong
  lockout refuses every user of that key, so one refusal - which a
  false-positive-prone benign user produces regularly - is not enough
  evidence. (The first version required 1; raised after the first
  evaluation found agents locking out too many benign sessions, L6b-10.)
  The rule-based fallback locks out after 4 consecutive refusals, so this
  never changes what it does.
- `challenge` while one is already pending changes nothing.
"""
from app.core.defense.bandit import clamp_bias
from app.core.defense.rl.features import SessionSnapshot
from app.db.models import SessionAction

TIGHTEN_STEP = 0.25
RELAX_STEP = 0.25
LOCKOUT_MIN_REFUSED = 2

# Fixed action order: the DQN's output index i means ACTION_ORDER[i].
ACTION_ORDER: tuple[SessionAction, ...] = (
    SessionAction.MAINTAIN,
    SessionAction.TIGHTEN,
    SessionAction.RELAX,
    SessionAction.CHALLENGE,
    SessionAction.LOCKOUT,
)

# Actions that count as the agent treating the session as suspicious
# (the reward table's "tightened / challenged / locked out").
INTERVENTIONS = frozenset(
    {SessionAction.TIGHTEN, SessionAction.CHALLENGE, SessionAction.LOCKOUT}
)


def next_bias(bias: float, action: SessionAction) -> float:
    if action == SessionAction.TIGHTEN:
        return clamp_bias(bias + TIGHTEN_STEP)
    if action == SessionAction.RELAX:
        return clamp_bias(bias - RELAX_STEP)
    return clamp_bias(bias)


def guard(action: SessionAction, snapshot: SessionSnapshot) -> SessionAction:
    """The action actually carried out (see the module docstring)."""
    if action == SessionAction.LOCKOUT and snapshot.refused_count < LOCKOUT_MIN_REFUSED:
        return SessionAction.MAINTAIN
    if action == SessionAction.CHALLENGE and snapshot.challenge_pending:
        return SessionAction.MAINTAIN
    return action
