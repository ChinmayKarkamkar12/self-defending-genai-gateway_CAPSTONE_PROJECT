import math

import numpy as np
import pytest

from app.core.defense.features import (
    FEATURE_NAMES,
    N_FEATURES,
    FeatureInputs,
    build_features,
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
    x = build_features(FeatureInputs(threat_score=BENIGN, pii_entity_count=3, hour_utc=7.5))
    assert np.array_equal(features_from_dict(features_to_dict(x)), x)


def test_values_are_scaled_and_capped():
    x = features_to_dict(
        build_features(
            FeatureInputs(
                threat_score=BENIGN,
                scan_windows=500,
                scan_truncated=True,
                pii_entity_count=99,
                team_requests_this_minute=10_000,
            )
        )
    )
    assert x["scan_windows"] == 1.0
    assert x["scan_truncated"] == 1.0
    assert x["pii_entities"] == 1.0
    assert x["team_request_rate"] == 1.0
    assert x["system_prompt_attack"] == 0.0


def test_attack_logit_separates_saturated_scores():
    def logit(p):
        score = {"benign": 1 - p, "prompt_injection": p, "jailbreak": 0.0}
        return features_to_dict(build_features(FeatureInputs(threat_score=score)))["attack_logit"]

    assert logit(0.98) < logit(0.9999)
    assert logit(0.9999) - logit(0.98) > 0.4
    assert -1.0 <= logit(0.0) < logit(0.5) == 0.0 < logit(1.0) <= 1.0


def test_hour_on_unit_circle():
    x = features_to_dict(build_features(FeatureInputs(threat_score=BENIGN, hour_utc=6.0)))
    assert math.isclose(x["hour_sin"], 1.0)
    assert abs(x["hour_cos"]) < 1e-9


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
