"""See project_plan/06a-adaptive-defense-bandit.md §8."""
import json

import numpy as np
import pytest

from app.core.defense.bandit import LinUCB, new_bandit
from app.core.defense.features import FeatureInputs, build_features
from app.db.models import DefenseAction

A = DefenseAction


def ctx(p_attack: float, injection_share: float = 1.0) -> np.ndarray:
    score = {
        "benign": 1.0 - p_attack,
        "prompt_injection": p_attack * injection_share,
        "jailbreak": p_attack * (1.0 - injection_share),
    }
    return build_features(FeatureInputs(threat_score=score))


def random_contexts(n: int, seed: int) -> list[np.ndarray]:
    rng = np.random.default_rng(seed)
    return [ctx(float(rng.uniform()), float(rng.uniform())) for _ in range(n)]


def test_action_selection_deterministic_given_seed():
    # A fresh, un-primed bandit scores every arm identically, so the
    # seeded tie-breaker decides - and the same seed must replay the same
    # sequence of choices and updates exactly.
    def run(seed: int) -> list[DefenseAction]:
        bandit = LinUCB(seed=seed)
        rng = np.random.default_rng(123)
        choices = []
        for x in random_contexts(60, seed=99):
            action = bandit.select(x).action
            choices.append(action)
            bandit.update(x, action, float(rng.uniform(-1, 1)))
        return choices

    assert run(7) == run(7)
    assert len(set(run(7))) > 1


def test_update_changes_future_action_probabilities():
    # The core "it's actually adaptive" test: keep punishing `allow` in one
    # context and the bandit's estimate for allow drops - there and in
    # similar contexts - until it stops choosing allow.
    bandit = new_bandit(alpha=0.5, seed=0)
    x = ctx(0.15)
    similar = ctx(0.18)

    before = bandit.select(x)
    before_similar = bandit.select(similar).arms[A.ALLOW].mean
    assert before.action == A.ALLOW

    means = [before.arms[A.ALLOW].mean]
    for _ in range(40):
        bandit.update(x, A.ALLOW, -1.0)
        means.append(bandit.select(x).arms[A.ALLOW].mean)

    after = bandit.select(x)
    assert after.action != A.ALLOW
    assert all(b < a for a, b in zip(means, means[1:], strict=False))
    assert bandit.select(similar).arms[A.ALLOW].mean < before_similar - 0.2


def test_feedback_in_one_region_needs_counter_evidence_elsewhere():
    # LinUCB is linear, so learning generalises across the whole feature
    # space, not just near the updated context: 40 unanimous "attack"
    # labels at p=0.15 also lower allow for p~0. That's why spot checks
    # sample allowed traffic too - benign labels there hold the clearly
    # benign region in place while the p=0.15 region tightens.
    x, far = ctx(0.15), ctx(0.0005)

    one_sided = new_bandit(seed=0)
    for _ in range(40):
        one_sided.update(x, A.ALLOW, -1.0)
    assert one_sided.select(far).action != A.ALLOW

    balanced = new_bandit(seed=0)
    for _ in range(40):
        balanced.update(x, A.ALLOW, -1.0)
        balanced.update(far, A.ALLOW, 1.0)
    assert balanced.select(x).action != A.ALLOW
    assert balanced.select(far).action == A.ALLOW


def test_uncertainty_shrinks_with_feedback():
    bandit = new_bandit(seed=0)
    x = ctx(0.5)
    before = bandit.select(x)
    for _ in range(20):
        bandit.update(x, A.ESCALATE_TO_HUMAN, 0.45)
    after = bandit.select(x)
    assert after.arms[A.ESCALATE_TO_HUMAN].width < before.arms[A.ESCALATE_TO_HUMAN].width
    # Other arms got no feedback, so their uncertainty is unchanged.
    assert after.arms[A.BLOCK].width == pytest.approx(before.arms[A.BLOCK].width)


@pytest.mark.parametrize(
    ("p_attack", "action"),
    [
        (0.0005, A.ALLOW),
        (0.05, A.ALLOW),
        (0.45, A.REDACT_AND_ALLOW),
        (0.7, A.ESCALATE_TO_HUMAN),
        (0.95, A.BLOCK),
        (0.9999, A.BLOCK),
    ],
)
def test_warm_start_prior_follows_reward_bands(p_attack, action):
    # Before any feedback the policy should look like reward.py's
    # documented bands, not like random exploration.
    bandit = new_bandit(seed=0)
    assert bandit.select(ctx(p_attack), alpha=0.0).action == action


def test_masked_arm_never_chosen_even_when_favoured():
    bandit = new_bandit(seed=0)
    x = ctx(0.995)
    for _ in range(200):
        bandit.update(x, A.ALLOW, 1.0)
    assert bandit.select(x).action == A.ALLOW
    masked = frozenset({A.ALLOW})
    for alpha in (0.0, 0.5, 5.0):
        for bias in (-1.0, 0.0):
            selection = bandit.select(x, alpha=alpha, escalation_bias=bias, masked=masked)
            assert selection.action != A.ALLOW
            assert selection.arms[A.ALLOW].masked


def test_everything_masked_is_an_error():
    with pytest.raises(ValueError):
        new_bandit().select(ctx(0.5), masked=frozenset(A))


def test_escalation_bias_tightens_and_relaxes():
    bandit = new_bandit(seed=0)
    strictness = [A.ALLOW, A.REDACT_AND_ALLOW, A.ESCALATE_TO_HUMAN, A.BLOCK]

    def level(p, bias):
        return strictness.index(bandit.select(ctx(p), alpha=0.0, escalation_bias=bias).action)

    assert level(0.3, 1.0) > level(0.3, 0.0)
    assert level(0.65, -1.0) < level(0.65, 0.0)
    # The bias is clamped and can't block a clearly benign request.
    assert bandit.select(ctx(0.0005), alpha=0.0, escalation_bias=50.0).action == A.ALLOW


def test_bias_does_not_change_learned_estimates():
    bandit = new_bandit(seed=0)
    neutral = bandit.select(ctx(0.4), escalation_bias=0.0)
    tight = bandit.select(ctx(0.4), escalation_bias=1.0)
    for action in A:
        assert tight.arms[action].mean == neutral.arms[action].mean


def test_state_roundtrip_through_json():
    bandit = new_bandit(seed=0)
    for x in random_contexts(10, seed=1):
        bandit.update(x, A.BLOCK, 0.5)
    restored = LinUCB.from_state(json.loads(json.dumps(bandit.to_state())))
    for x in random_contexts(20, seed=2):
        a, b = bandit.select(x), restored.select(x)
        assert a.action == b.action
        assert a.arms[A.BLOCK].mean == pytest.approx(b.arms[A.BLOCK].mean)
    assert restored.update_counts.tolist() == [0, 0, 10, 0]


def test_prior_does_not_count_as_feedback():
    assert new_bandit().update_counts.tolist() == [0, 0, 0, 0]


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda s: s.update(format=99),
        lambda s: s.update(n_features=3),
        lambda s: s.update(actions=["allow", "block"]),
        lambda s: s.update(A=s["A"][:2]),
        lambda s: s["b"][0].__setitem__(0, float("nan")),
    ],
)
def test_corrupt_state_rejected(corrupt):
    state = new_bandit().to_state()
    corrupt(state)
    with pytest.raises(ValueError):
        LinUCB.from_state(state)


def test_non_finite_inputs_rejected():
    bandit = new_bandit()
    x = ctx(0.5)
    bad = x.copy()
    bad[1] = np.nan
    with pytest.raises(ValueError):
        bandit.select(bad)
    with pytest.raises(ValueError):
        bandit.update(x, A.ALLOW, float("nan"))
    with pytest.raises(ValueError):
        bandit.select(x, escalation_bias=float("nan"))
    with pytest.raises(ValueError):
        bandit.select(x[:3])
