import numpy as np
import pytest

from app.core.defense.features import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    N_FEATURES,
    SYSTEM_WEIGHT,
    FeatureInputs,
    build_features,
    effective_attack_probability,
    features_from_dict,
    features_to_dict,
)

BENIGN = {"benign": 0.99, "prompt_injection": 0.005, "jailbreak": 0.005}


def test_vector_layout_matches_documented_names():
    x = build_features(FeatureInputs(threat_score=BENIGN))
    assert x.shape == (N_FEATURES,)
    assert list(features_to_dict(x)) == list(FEATURE_NAMES)
    assert x[0] == 1.0


def test_dict_roundtrip():
    x = build_features(FeatureInputs(threat_score=BENIGN, pii_entity_count=3))
    assert np.array_equal(features_from_dict(features_to_dict(x)), x)


def test_values_are_scaled_and_capped():
    x = features_to_dict(
        build_features(
            FeatureInputs(
                threat_score=BENIGN,
                scan_windows=500,
                scan_truncated=True,
                pii_entity_count=99,
            )
        )
    )
    assert x["scan_windows"] == 1.0
    assert x["scan_truncated"] == 1.0
    assert x["pii_entities"] == 1.0
    assert x["system_prompt_attack"] == 0.0


def test_attack_logit_separates_saturated_scores():
    def logit(p):
        score = {"benign": 1 - p, "prompt_injection": p, "jailbreak": 0.0}
        return features_to_dict(build_features(FeatureInputs(threat_score=score)))["attack_logit"]

    assert logit(0.98) < logit(0.9999)
    assert logit(0.9999) - logit(0.98) > 0.4
    assert -1.0 <= logit(0.0) < logit(0.5) == 0.0 < logit(1.0) <= 1.0


def test_v2_layout_has_no_clock_or_rate_features():
    # Removed in FEATURE_VERSION 2: fitted noise, and the rate was
    # attacker-controlled (features.py docstring).
    assert FEATURE_VERSION == 2
    for removed in ("hour_sin", "hour_cos", "team_request_rate"):
        assert removed not in FEATURE_NAMES


def test_system_prompt_features():
    def features(p_conv, p_system):
        return features_to_dict(
            build_features(
                FeatureInputs(
                    threat_score={"benign": 1 - p_conv, "prompt_injection": p_conv, "jailbreak": 0},
                    system_prompt_threat_score={
                        "benign": 1 - p_system,
                        "prompt_injection": p_system,
                        "jailbreak": 0,
                    },
                )
            )
        )

    x = features(0.5, 0.8)
    assert x["system_prompt_attack"] == pytest.approx(0.8)
    assert x["system_x_conversation"] == pytest.approx(0.4)


def test_effective_attack_probability():
    def p_eff(p_conv, p_system=None):
        system = (
            None
            if p_system is None
            else {"benign": 1 - p_system, "prompt_injection": p_system, "jailbreak": 0}
        )
        return effective_attack_probability(
            FeatureInputs(
                threat_score={"benign": 1 - p_conv, "prompt_injection": p_conv, "jailbreak": 0},
                system_prompt_threat_score=system,
            )
        )

    assert p_eff(0.4) == pytest.approx(0.4)
    # A fully flagged system prompt alone stays in the allow band (< 0.33).
    assert p_eff(0.0, 1.0) == pytest.approx(SYSTEM_WEIGHT)
    assert SYSTEM_WEIGHT < 0.33
    assert p_eff(0.5, 1.0) == pytest.approx(1 - 0.5 * (1 - SYSTEM_WEIGHT))


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_non_finite_score_refused_not_read_as_benign(bad):
    # max(0.0, nan) == 0.0 in Python - a NaN must not quietly become "benign".
    with pytest.raises(ValueError):
        build_features(
            FeatureInputs(threat_score={"benign": bad, "prompt_injection": 0.0, "jailbreak": 0.0})
        )
    with pytest.raises(ValueError):
        build_features(
            FeatureInputs(
                threat_score=BENIGN,
                system_prompt_threat_score={
                    "benign": 0.5,
                    "prompt_injection": bad,
                    "jailbreak": 0.0,
                },
            )
        )
