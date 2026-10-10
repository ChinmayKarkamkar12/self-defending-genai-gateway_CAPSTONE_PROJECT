"""Reward function for the tactical bandit. See
project_plan/06a-adaptive-defense-bandit.md §2.

The reward for one decision depends only on the action taken and the
request's true label (attack / benign), once that label is known:

| true label \\ action | allow | redact_and_allow | block | escalate_to_human |
|---------------------|-------|------------------|-------|-------------------|
| benign              | +1.0  | +0.5             | -0.3  | -0.1              |
| attack              | -1.0  |  0.0             | +0.5  | +0.45             |

Why each weight:

- allow: +1.0 for serving benign traffic untouched (the gateway's whole
  job); -1.0 for letting an attack through, the worst outcome.
- block: +0.5 for stopping an attack. -0.3 for blocking benign traffic: a
  false positive is bad (a user is refused for nothing), but less bad than
  a missed attack.
- redact_and_allow: the flagged windows are cut out and the rest goes
  upstream. On benign traffic the user still gets an answer but a degraded
  one (+0.5, half of a clean allow). On an attack the attack text itself is
  removed, so it is usually neutralised, but the request still costs a
  provider call and remnants can survive across window boundaries - 0.0,
  neither a success nor a failure.
- escalate_to_human: the request is held (blocked) and a person reviews
  it. On an attack that is nearly as good as a block (+0.45 vs +0.5) - the
  difference is the reviewer's time - and it also produces a labelled
  example. On benign traffic it is better than a silent false block (-0.1
  vs -0.3): the user is told it is under review and a person clears it.

Why these values and not round ones: with expected reward linear in the
attack probability p, each action should be the best choice somewhere,
in a sensible order. These weights give (calibrated p):

    allow  for p < 0.33,   redact  for 0.33 - 0.57,
    escalate for 0.57 - 0.80,   block  for p > 0.80

A first draft (redact -0.5 on attacks, escalate -0.2 / +0.4) left redact
and escalate never optimal at any p - two dead arms - which is why the
values were adjusted. `expected_reward` and `test_reward.py` check these
crossover points.

The bandit's warm-start policy (bandit.apply_calibrated_prior) is a ridge
fit to these expected rewards, so its bands are close to, not exactly,
the ones above. Measured (alpha=0, no feedback): allow < 0.34 < redact <
0.58 < escalate < 0.81 < block; test_bandit.py pins them to within 0.05.
Before the prior's ridge was lowered they had drifted to 0.23 / 0.56 /
0.88 - see bandit.PRIOR_RIDGE.
"""
from app.db.models import DefenseAction, ThreatLabel

REWARD_TABLE: dict[ThreatLabel, dict[DefenseAction, float]] = {
    ThreatLabel.BENIGN: {
        DefenseAction.ALLOW: 1.0,
        DefenseAction.REDACT_AND_ALLOW: 0.5,
        DefenseAction.BLOCK: -0.3,
        DefenseAction.ESCALATE_TO_HUMAN: -0.1,
    },
    ThreatLabel.ATTACK: {
        DefenseAction.ALLOW: -1.0,
        DefenseAction.REDACT_AND_ALLOW: 0.0,
        DefenseAction.BLOCK: 0.5,
        DefenseAction.ESCALATE_TO_HUMAN: 0.45,
    },
}


def proxy_reward(action: DefenseAction | str, label: ThreatLabel | str) -> float:
    """Reward for taking `action` on a request whose true label is `label`."""
    return REWARD_TABLE[ThreatLabel(label)][DefenseAction(action)]


def expected_reward(action: DefenseAction | str, p_attack: float) -> float:
    """Expected reward of `action` if the request is an attack with
    probability `p_attack`. Used to build the bandit's warm-start prior."""
    return (1.0 - p_attack) * proxy_reward(action, ThreatLabel.BENIGN) + p_attack * proxy_reward(
        action, ThreatLabel.ATTACK
    )
