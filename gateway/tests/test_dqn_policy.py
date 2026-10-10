"""Exported DQN weights: numpy runtime and loading checks. See
app/core/defense/rl/dqn.py."""
import numpy as np
import pytest

from app.core.defense.rl.actions import ACTION_ORDER
from app.core.defense.rl.dqn import DEFAULT_WEIGHTS_PATH, DQNPolicy, save_weights
from app.core.defense.rl.features import (
    N_SESSION_FEATURES,
    SESSION_FEATURE_NAMES,
    SessionSnapshot,
    build_session_features,
)
from app.db.models import SessionAction

N_ACTIONS = len(ACTION_ORDER)


def random_layers(seed: int = 0, sizes=(N_SESSION_FEATURES, 8, 8, N_ACTIONS)):
    rng = np.random.default_rng(seed)
    return [
        (rng.normal(size=(n_out, n_in)), rng.normal(size=n_out))
        for n_in, n_out in zip(sizes[:-1], sizes[1:], strict=True)
    ]


def test_round_trip_and_forward_pass(tmp_path):
    layers = random_layers()
    path = tmp_path / "w.npz"
    save_weights(path, layers)
    policy = DQNPolicy.load(path)

    snap = SessionSnapshot(request_count=3, outcome_counts={"block": 3}, consecutive_refused=3)
    x = build_session_features(snap)
    h = x
    for i, (w, b) in enumerate(layers):
        h = w @ h + b
        h = np.maximum(h, 0) if i < len(layers) - 1 else h
    assert policy.q_values(x) == pytest.approx(h, rel=1e-5)  # stored as float32
    assert policy.decide(snap) == ACTION_ORDER[int(np.argmax(h))]


def test_decides_the_argmax_action():
    # A single linear layer that only rewards "lockout".
    w = np.zeros((len(ACTION_ORDER), N_SESSION_FEATURES))
    b = np.zeros(len(ACTION_ORDER))
    b[ACTION_ORDER.index(SessionAction.LOCKOUT)] = 1.0
    assert DQNPolicy([(w, b)]).decide(SessionSnapshot()) == SessionAction.LOCKOUT


def test_mismatched_layout_is_refused(tmp_path):
    path = tmp_path / "w.npz"
    save_weights(path, random_layers())
    data = dict(np.load(path))
    data["feature_names"] = np.array(list(reversed(SESSION_FEATURE_NAMES)))
    np.savez(path, **data)
    with pytest.raises(ValueError, match="layout"):
        DQNPolicy.load(path)

    data["feature_names"] = np.array(SESSION_FEATURE_NAMES)
    data["actions"] = np.array(["lockout", "maintain", "tighten", "relax", "challenge"])
    np.savez(path, **data)
    with pytest.raises(ValueError, match="action order"):
        DQNPolicy.load(path)


def test_bad_shapes_and_values_are_refused():
    with pytest.raises(ValueError):
        DQNPolicy(random_layers(sizes=(N_SESSION_FEATURES + 1, 4, len(ACTION_ORDER))))
    with pytest.raises(ValueError):
        DQNPolicy(random_layers(sizes=(N_SESSION_FEATURES, 4, 3)))
    layers = random_layers()
    layers[0][0][0, 0] = np.nan
    with pytest.raises(ValueError):
        DQNPolicy(layers)


def test_loading_never_unpickles(tmp_path):
    path = tmp_path / "w.npz"
    save_weights(path, random_layers())
    data = dict(np.load(path))
    data["W0"] = np.array([object()], dtype=object)
    np.savez(path, **data)
    with pytest.raises(ValueError):
        DQNPolicy.load(path)


@pytest.mark.skipif(not DEFAULT_WEIGHTS_PATH.exists(), reason="no trained weights shipped")
def test_shipped_weights_load():
    policy = DQNPolicy.load()
    assert policy.decide(SessionSnapshot(request_count=1)) in ACTION_ORDER
