"""See project_plan/06a-adaptive-defense-bandit.md §8."""
import json

import numpy as np
import pytest

from app.core.defense.bandit import MIN_BIAS, AppliedUpdate, LinUCB, new_bandit, safety_mask
from app.core.defense.features import FeatureInputs, build_features
from app.db.models import DefenseAction

A = DefenseAction


STRICTNESS = [A.ALLOW, A.REDACT_AND_ALLOW, A.ESCALATE_TO_HUMAN, A.BLOCK]


def ctx(
    p_attack: float, injection_share: float = 1.0, system: float | None = None, **counts
) -> np.ndarray:
    score = {
        "benign": 1.0 - p_attack,
        "prompt_injection": p_attack * injection_share,
        "jailbreak": p_attack * (1.0 - injection_share),
    }
    system_score = (
        None
        if system is None
        else {"benign": 1.0 - system, "prompt_injection": system, "jailbreak": 0.0}
    )
    return build_features(
        FeatureInputs(threat_score=score, system_prompt_threat_score=system_score, **counts)
    )


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
    assert level(0.65, MIN_BIAS) < level(0.65, 0.0)
    # The bias is clamped and can't block a clearly benign request.
    assert bandit.select(ctx(0.0005), alpha=0.0, escalation_bias=50.0).action == A.ALLOW


def test_negative_bias_is_clamped_and_cannot_open_the_defense():
    # G4: at bias -1 a p=0.6 request used to be allowed and p 0.5-0.95 was
    # redacted. The Redis key is unauthenticated, so the floor is -0.3.
    bandit = new_bandit(seed=0)
    for p in (0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        low = bandit.select(ctx(p), alpha=0.0, escalation_bias=-1.0)
        floor = bandit.select(ctx(p), alpha=0.0, escalation_bias=MIN_BIAS)
        assert low.action == floor.action
        assert low.arms[A.ALLOW].score == floor.arms[A.ALLOW].score
    assert bandit.select(ctx(0.6), alpha=0.0, escalation_bias=-1.0).action != A.ALLOW


def test_safety_mask_thresholds():
    assert safety_mask(0.5, 0.99, 0.95) == frozenset()
    assert safety_mask(0.96, 0.99, 0.95) == frozenset({A.REDACT_AND_ALLOW})
    assert safety_mask(0.995, 0.99, 0.95) == frozenset({A.ALLOW, A.REDACT_AND_ALLOW})
    # The redact threshold is optional (offline callers), allow-only then.
    assert safety_mask(0.995, 0.99) == frozenset({A.ALLOW})


def test_near_certain_attack_is_never_half_passed():
    bandit = new_bandit(seed=0)
    x = ctx(0.96)
    for _ in range(200):
        bandit.update(x, A.REDACT_AND_ALLOW, 1.0)
    masked = safety_mask(0.96, 0.99, 0.95)
    for alpha in (0.0, 0.5, 5.0):
        for bias in (-1.0, 0.0):
            action = bandit.select(x, alpha=alpha, escalation_bias=bias, masked=masked).action
            assert action not in (A.ALLOW, A.REDACT_AND_ALLOW)


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
        lambda s: s.update(data_A=s["data_A"][:2]),
        lambda s: s.update(prior_A=s["prior_A"][:2]),
        lambda s: s["data_b"][0].__setitem__(0, float("nan")),
        lambda s: s["prior_b"][0].__setitem__(0, float("inf")),
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


def _band_edges(bandit: LinUCB) -> list[tuple[float, DefenseAction]]:
    edges, previous = [], None
    for p in np.round(np.arange(0.0, 1.0001, 0.01), 2):
        action = bandit.select(ctx(float(p)), alpha=0.0).action
        if action != previous:
            edges.append((float(p), action))
            previous = action
    return edges


def test_warm_start_bands_match_reward_design():
    # reward.py's crossovers under calibrated scores are 0.33 / 0.57 / 0.80.
    # At ridge 1.0 shrinkage moved them to 0.22 / 0.58 / 0.91.
    edges = _band_edges(new_bandit(seed=0))
    assert [a for _, a in edges] == STRICTNESS[:2] + [A.ESCALATE_TO_HUMAN, A.BLOCK]
    for (p, _), expected in zip(edges[1:], (0.33, 0.57, 0.80), strict=True):
        assert abs(p - expected) <= 0.05


def test_attacker_controlled_counts_never_relax_the_decision():
    # Window count, PII count and truncation are chosen by whoever writes
    # the prompt. With neutral counts as the baseline, no combination may
    # produce a laxer action. At v1 (prior covered 1-8 windows, 0-3 PII)
    # 32 windows turned a p=0.6 escalate into a redact.
    bandit = new_bandit(seed=0)
    for p in np.arange(0.0, 1.0001, 0.05):
        base = STRICTNESS.index(bandit.select(ctx(float(p))).action)
        for windows in (1, 8, 16, 32):
            for pii in (0, 3, 10):
                for truncated in (False, True):
                    x = ctx(
                        float(p),
                        scan_windows=windows,
                        pii_entity_count=pii,
                        scan_truncated=truncated,
                    )
                    assert STRICTNESS.index(bandit.select(x).action) >= base, (p, windows, pii)


def test_flagged_system_prompt_tightens_borderline_but_not_benign():
    bandit = new_bandit(seed=0)

    def level(p, system=None):
        return STRICTNESS.index(bandit.select(ctx(p, system=system), alpha=0.0).action)

    # A defensive system prompt (scored 0.98+ by module 5) on a benign
    # conversation must still be allowed...
    assert level(0.0, system=0.99) == 0
    assert level(0.0, system=1.0) == 0
    # ...but on a borderline conversation it counts as evidence.
    assert level(0.5, system=1.0) > level(0.5)


def test_safety_mask_system_prompt_rule():
    assert A.ALLOW in safety_mask(0.35, 0.99, 0.999, p_system=0.9995)
    assert A.ALLOW not in safety_mask(0.35, 0.99, 0.999, p_system=0.99)
    assert A.ALLOW not in safety_mask(0.1, 0.99, 0.999, p_system=1.0)


def test_one_sided_labels_at_low_weight_need_far_more_evidence():
    # L6a-10: automatic attack labels on allowed p 0.05-0.2 requests pull
    # p=0 traffic away from allow (the model is linear, so the evidence
    # generalises). At the output-scan weight (0.2) that takes ~4x as many
    # labels - time for the human reviews queued with each one to replace
    # them. When it does happen, the redact on a p~0 request cuts nothing
    # (strip.py's minimum window; test_bandit_stage.py).
    def labels_until_benign_moves(weight: float) -> int:
        bandit = new_bandit(seed=0)
        rng = np.random.default_rng(1)
        for n in range(1, 500):
            bandit.update(ctx(float(rng.uniform(0.05, 0.2))), A.ALLOW, -1.0, weight=weight)
            if bandit.select(ctx(0.0)).action != A.ALLOW:
                return n
        return 500

    assert labels_until_benign_moves(0.2) >= 3 * labels_until_benign_moves(1.0)


def _labels_to_recover(gamma: float) -> int:
    # 5,000 drift labels say "redact is fine" for p=0.97 traffic, then the
    # drift ends and every label says attack.
    bandit = new_bandit(gamma=gamma, seed=0)
    x = ctx(0.97)
    for _ in range(5000):
        bandit.update(x, A.REDACT_AND_ALLOW, 0.5)
        bandit.update(x, A.BLOCK, -0.3)
    assert bandit.select(x, alpha=0.0).action == A.REDACT_AND_ALLOW
    n = 0
    while bandit.select(x, alpha=0.0).action == A.REDACT_AND_ALLOW:
        bandit.update(x, A.REDACT_AND_ALLOW, 0.0)
        n += 1
        assert n < 20_000
    return n


def test_discounting_recovers_from_drift_much_faster():
    never_forget, discounted = _labels_to_recover(1.0), _labels_to_recover(0.999)
    assert discounted < never_forget / 3
    assert discounted < 500


def test_prior_is_not_discounted():
    bandit = new_bandit(gamma=0.9, seed=0)
    prior_a = bandit.prior_A.copy()
    for _ in range(200):
        bandit.update(ctx(0.5), A.BLOCK, 0.5)
    np.testing.assert_array_equal(bandit.prior_A, prior_a)


def test_revert_withdraws_an_update_exactly():
    bandit = new_bandit(gamma=0.99, seed=0)
    for x in random_contexts(5, seed=3):
        bandit.update(x, A.ALLOW, 1.0)
    target = ctx(0.4)
    applied = bandit.update(target, A.ALLOW, -1.0, weight=0.2)
    later = random_contexts(7, seed=4)
    for x in later:
        bandit.update(x, A.ALLOW, 1.0)

    reference = new_bandit(gamma=0.99, seed=0)
    for x in random_contexts(5, seed=3):
        reference.update(x, A.ALLOW, 1.0)
    # Same arm step, so later updates decay the same way.
    reference.arm_steps[0] += 1
    reference.update_counts[0] += 1
    reference.data_A[0] *= 0.99
    reference.data_b[0] *= 0.99
    for x in later:
        reference.update(x, A.ALLOW, 1.0)

    bandit.revert(target, A.ALLOW, -1.0, applied)
    np.testing.assert_allclose(bandit.data_A, reference.data_A, atol=1e-12)
    np.testing.assert_allclose(bandit.data_b, reference.data_b, atol=1e-12)
    assert bandit.update_counts[0] == 12


def test_revert_rejects_an_update_from_the_future():
    bandit = new_bandit(seed=0)
    with pytest.raises(ValueError):
        bandit.revert(ctx(0.4), A.ALLOW, 1.0, AppliedUpdate(arm_step=5, weight=1.0))


def test_confidence_is_zero_before_feedback_and_grows_with_it():
    # Measured against the combined A, day-one confidence read ~0.7 with
    # no feedback at all.
    bandit = new_bandit(seed=0)
    x = ctx(0.5)
    assert bandit.select(x).confidence == 0.0
    chosen = bandit.select(x).action
    previous = 0.0
    for _ in range(3):
        for _ in range(20):
            bandit.update(x, chosen, 0.45)
        confidence = bandit.select(x).confidence
        assert previous < confidence < 1.0
        previous = confidence


def test_gamma_validated():
    for gamma in (0.0, 1.5, -1.0):
        with pytest.raises(ValueError):
            LinUCB(gamma=gamma)
