"""Exported DQN weights: numpy runtime and loading checks. See
app/core/defense/rl/dqn.py."""
import numpy as np
import pytest

from app.core.defense.rl.actions import ACTION_ORDER
from app.core.defense.rl.dqn import (
    DEFAULT_WEIGHTS_PATH,
    DQNEnsemble,
    DQNPolicy,
    load_dqn,
    save_ensemble,
    save_weights,
)
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
    # Through the gateway's loader: the shipped file may be one network or
    # a voting ensemble (run 3 ships an ensemble).
    policy = load_dqn()
    assert policy.decide(SessionSnapshot(request_count=1)) in ACTION_ORDER


# ------------------------------------------------------------- ensembles


def bias_only(action: SessionAction, strength: float = 1.0):
    """A one-layer network whose Q-values are constant, preferring `action`."""
    w = np.zeros((N_ACTIONS, N_SESSION_FEATURES))
    b = np.zeros(N_ACTIONS)
    b[ACTION_ORDER.index(action)] = strength
    return [(w, b)]


def test_ensemble_majority_vote_wins():
    members = [
        DQNPolicy(bias_only(SessionAction.TIGHTEN)),
        DQNPolicy(bias_only(SessionAction.TIGHTEN)),
        DQNPolicy(bias_only(SessionAction.LOCKOUT, strength=50.0)),
    ]
    # One very confident member is still outvoted.
    assert DQNEnsemble(members).decide(SessionSnapshot()) == SessionAction.TIGHTEN


def test_ensemble_tie_goes_to_the_highest_summed_q():
    members = [
        DQNPolicy(bias_only(SessionAction.TIGHTEN, strength=1.0)),
        DQNPolicy(bias_only(SessionAction.CHALLENGE, strength=2.0)),
    ]
    assert DQNEnsemble(members).decide(SessionSnapshot()) == SessionAction.CHALLENGE


def test_ensemble_round_trip(tmp_path):
    path = tmp_path / "ensemble.npz"
    member_layers = [random_layers(seed=k) for k in range(5)]
    save_ensemble(path, member_layers)
    policy = load_dqn(path)

    assert isinstance(policy, DQNEnsemble)
    assert len(policy.members) == 5
    snap = SessionSnapshot(request_count=4, outcome_counts={"block": 2}, consecutive_refused=2)
    x = build_session_features(snap)
    for member, layers in zip(policy.members, member_layers, strict=True):
        assert member.q_values(x) == pytest.approx(DQNPolicy(layers).q_values(x), rel=1e-5)
    with pytest.raises(ValueError, match="ensemble"):
        DQNPolicy.load(path)


def test_load_dqn_reads_single_network_files(tmp_path):
    path = tmp_path / "single.npz"
    save_weights(path, random_layers())
    assert isinstance(load_dqn(path), DQNPolicy)


@pytest.mark.parametrize("n_members", [0, 16])
def test_ensemble_size_is_bounded(tmp_path, n_members):
    path = tmp_path / "ensemble.npz"
    save_ensemble(path, [random_layers()])
    data = dict(np.load(path))
    data["n_members"] = np.array(n_members)
    np.savez(path, **data)
    with pytest.raises(ValueError, match="members"):
        load_dqn(path)


def test_ensemble_member_with_bad_weights_is_refused(tmp_path):
    path = tmp_path / "ensemble.npz"
    save_ensemble(path, [random_layers(seed=0), random_layers(seed=1)])
    data = dict(np.load(path))
    data["m1_W0"] = np.full_like(data["m1_W0"], np.nan)
    np.savez(path, **data)
    with pytest.raises(ValueError, match="non-finite"):
        load_dqn(path)
