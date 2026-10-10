"""Reward for the session agent. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2.

Three parts, kept separate so each can be reported (and the shaping
ablated) on its own:

1. Terminal reward, once per session when its label is known - the plan's
   table, unchanged:

   | session \\ agent      | intervened (tighten / challenge / lockout) | never intervened |
   |----------------------|---------------------------------------------|------------------|
   | benign               | -0.5                                        | +1.0             |
   | attack               | +1.5                                        | -2.0             |

   Two additions:
   - an attack session in which an attack request was *allowed* (a
     breach) gets -2.0 whatever the agent did. Intervening and still
     letting the attack through is not a success;
   - a benign session the agent *locked out* gets WRONGFUL_LOCKOUT_REWARD
     = -2.0 instead of -0.5: as bad as a breach. A session is a whole API
     key (L6b-1), so a wrongful lockout refuses every user of an
     application. Under the plan's -0.5, the first evaluation (2026-10-10)
     found 3 of 5 trained agents earned their higher reward partly by
     locking out 2-5x more benign sessions than the rule (L6b-5, L6b-10).

2. Request reward, every step: what module 6a's outcome on the session's
   next request earned under 6a's own table (app/core/defense/reward.py),
   times REQUEST_REWARD_WEIGHT. This is what makes the actions differ in
   cost. Under the plan's table alone, tighten and lockout earn the same,
   but lockout ends the risk, so an agent learns "lock out on any
   suspicion". Here a lockout refuses every request the session would
   still have sent, each costing a benign block (-0.3) on a benign session,
   so locking out a legitimate user is clearly worse than tightening.
   The weight keeps a 15-request session's request rewards (at most +-3)
   from swamping the terminal reward.

3. Shaping (optional, SHAPING_COEF in the simulator): the plan's "fraction
   of the threat score change". It is applied in potential-based form,
   F = coef * (gamma * phi(s') - phi(s)) with phi = the session's maximum
   recent attack probability and phi(terminal) = 0. Potential-based
   shaping provably leaves the optimal policy unchanged (Ng, Harada &
   Russell, 1999), so it can only change how fast the agent learns. A raw
   score-change bonus would not have that guarantee, and since the scores
   don't depend on the agent's action it would mostly add noise.
   training/evaluate_rl_agent.py reports agents trained with and without it.
"""
from app.core.defense.reward import proxy_reward
from app.core.defense.rl.features import SessionSnapshot
from app.db.models import DefenseAction, ThreatLabel

TERMINAL_REWARD: dict[tuple[ThreatLabel, bool], float] = {
    (ThreatLabel.BENIGN, False): 1.0,
    (ThreatLabel.BENIGN, True): -0.5,
    (ThreatLabel.ATTACK, True): 1.5,
    (ThreatLabel.ATTACK, False): -2.0,
}
BREACH_REWARD = -2.0
WRONGFUL_LOCKOUT_REWARD = -2.0
REQUEST_REWARD_WEIGHT = 0.2


def terminal_reward(
    label: ThreatLabel, intervened: bool, breached: bool = False, locked_out: bool = False
) -> float:
    if label == ThreatLabel.ATTACK and breached:
        return BREACH_REWARD
    if label == ThreatLabel.BENIGN and locked_out:
        return WRONGFUL_LOCKOUT_REWARD
    return TERMINAL_REWARD[(ThreatLabel(label), bool(intervened))]


def request_reward(outcome: DefenseAction, is_attack: bool) -> float:
    label = ThreatLabel.ATTACK if is_attack else ThreatLabel.BENIGN
    return REQUEST_REWARD_WEIGHT * proxy_reward(outcome, label)


def potential(snapshot: SessionSnapshot) -> float:
    scores = list(snapshot.recent_scores)
    return max(scores) if scores else 0.0


def shaping(
    phi_before: float, phi_after: float, *, coef: float, gamma: float, terminal: bool
) -> float:
    if coef == 0.0:
        return 0.0
    return coef * ((0.0 if terminal else gamma * phi_after) - phi_before)
