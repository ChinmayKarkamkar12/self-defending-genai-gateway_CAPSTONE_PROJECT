"""See project_plan/06a-adaptive-defense-bandit.md §8."""
import pytest

from app.core.defense.reward import REWARD_TABLE, expected_reward, proxy_reward
from app.db.models import DefenseAction, ThreatLabel

A = DefenseAction


def test_reward_values_match_documented_weights():
    # The table in reward.py's docstring, cell by cell. Changing a weight
    # means changing the docstring (and the reasoning) too.
    documented = {
        (ThreatLabel.BENIGN, A.ALLOW): 1.0,
        (ThreatLabel.BENIGN, A.REDACT_AND_ALLOW): 0.5,
        (ThreatLabel.BENIGN, A.BLOCK): -0.3,
        (ThreatLabel.BENIGN, A.ESCALATE_TO_HUMAN): -0.1,
        (ThreatLabel.ATTACK, A.ALLOW): -1.0,
        (ThreatLabel.ATTACK, A.REDACT_AND_ALLOW): 0.0,
        (ThreatLabel.ATTACK, A.BLOCK): 0.5,
        (ThreatLabel.ATTACK, A.ESCALATE_TO_HUMAN): 0.45,
    }
    for (label, action), value in documented.items():
        assert proxy_reward(action, label) == value
    assert sum(len(row) for row in REWARD_TABLE.values()) == len(documented)


def test_accepts_plain_strings():
    assert proxy_reward("block", "attack") == 0.5


def test_unknown_values_rejected():
    with pytest.raises(ValueError):
        proxy_reward("shrug", "attack")
    with pytest.raises(ValueError):
        proxy_reward("allow", "maybe")


def _best(p_attack: float) -> DefenseAction:
    return max(DefenseAction, key=lambda a: expected_reward(a, p_attack))


@pytest.mark.parametrize(
    ("p_attack", "action"),
    [
        (0.0, A.ALLOW),
        (0.30, A.ALLOW),
        (0.36, A.REDACT_AND_ALLOW),
        (0.55, A.REDACT_AND_ALLOW),
        (0.60, A.ESCALATE_TO_HUMAN),
        (0.78, A.ESCALATE_TO_HUMAN),
        (0.82, A.BLOCK),
        (1.0, A.BLOCK),
    ],
)
def test_every_action_is_optimal_in_its_documented_band(p_attack, action):
    # allow < 1/3 < redact < 4/7 < escalate < 0.8 < block - no dead arms.
    assert _best(p_attack) == action
