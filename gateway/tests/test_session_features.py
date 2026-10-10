"""Session agent state vector. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2, §8."""
import math

import numpy as np
import pytest

from app.core.defense.rl.features import (
    N_SESSION_FEATURES,
    SESSION_FEATURE_NAMES,
    SessionSnapshot,
    build_session_features,
    session_features_to_dict,
)


def snapshot(**overrides) -> SessionSnapshot:
    values = dict(
        request_count=6,
        outcome_counts={"allow": 3, "block": 2, "escalate_to_human": 1},
        consecutive_refused=3,
        recent_scores=(0.0, 0.01, 0.2, 0.9, 0.99, 0.999),
        pii_requests=2,
        escalation_bias=0.25,
        challenge_pending=True,
    )
    values.update(overrides)
    return SessionSnapshot(**values)


def test_feature_vector_shape_and_ranges():
    x = build_session_features(snapshot())
    assert x.shape == (N_SESSION_FEATURES,) == (len(SESSION_FEATURE_NAMES),)
    assert np.all(np.isfinite(x))
    f = session_features_to_dict(x)
    assert f["request_count"] == pytest.approx(6 / 15)
    assert f["count_allow"] == pytest.approx(0.3)
    assert f["count_block"] == pytest.approx(0.2)
    assert f["count_redact"] == 0.0
    assert f["consecutive_refused"] == pytest.approx(0.6)
    assert f["score_last"] == pytest.approx(0.999)
    assert f["score_max"] == pytest.approx(0.999)
    assert f["score_slope"] > 0  # rising scores: the probe-then-escalate pattern
    assert f["share_high"] == pytest.approx(0.5)
    assert f["redaction_frequency"] == pytest.approx(2 / 6)
    assert f["escalation_bias"] == 0.25
    assert f["challenge_pending"] == 1.0
    # Everything except the bias (in [-0.3, 1]) and the slope is in [0, 1].
    for name, value in f.items():
        low = -1.0 if name in ("score_slope", "escalation_bias") else 0.0
        assert low <= value <= 1.0, name


def test_counts_saturate_on_long_sessions():
    f = session_features_to_dict(
        build_session_features(
            snapshot(
                request_count=400,
                outcome_counts={"block": 400},
                consecutive_refused=400,
                pii_requests=400,
            )
        )
    )
    assert f["request_count"] == f["count_block"] == f["consecutive_refused"] == 1.0
    assert f["redaction_frequency"] == 1.0


def test_empty_session_is_all_zero_but_bias():
    x = build_session_features(SessionSnapshot(escalation_bias=-0.3))
    f = session_features_to_dict(x)
    assert f.pop("escalation_bias") == -0.3
    assert all(v == 0.0 for v in f.values())


def test_slope_sign():
    falling = build_session_features(snapshot(recent_scores=(1.0, 0.5, 0.0)))
    flat = build_session_features(snapshot(recent_scores=(0.4, 0.4, 0.4)))
    i = SESSION_FEATURE_NAMES.index("score_slope")
    assert falling[i] == pytest.approx(-0.5)
    assert flat[i] == pytest.approx(0.0)


@pytest.mark.parametrize("bad", [math.nan, math.inf])
def test_non_finite_scores_are_refused(bad):
    with pytest.raises(ValueError):
        build_session_features(snapshot(recent_scores=(0.1, bad)))
    with pytest.raises(ValueError):
        build_session_features(snapshot(escalation_bias=bad))
