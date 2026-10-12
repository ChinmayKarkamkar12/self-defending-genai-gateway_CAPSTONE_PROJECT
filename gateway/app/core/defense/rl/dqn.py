"""The trained DQN agent, run without stable-baselines3. See
project_plan/06b-adaptive-defense-rl-session-agent.md §4-5.

training/train_rl_agent.py trains with stable-baselines3 and exports the
Q-network's layers to an .npz file. The gateway runs that file as a plain
numpy forward pass:

- no stable-baselines3 / gymnasium / pandas in the gateway image;
- no pickle: an SB3 .zip is loaded with cloudpickle, which executes code
  from the file. np.load(allow_pickle=False) only reads arrays;
- a forward pass through a 14-64-64-5 MLP takes microseconds.

The file records the feature layout and action order it was trained with;
loading refuses a mismatch instead of feeding the network the wrong
inputs (a wrong policy that looks fine).

A file can also hold an ensemble: several independently trained networks
that vote (DQNEnsemble; added for the third training run, after single
agents proved to vary too much between seeds). `load_dqn` reads either kind.
"""
from collections import Counter
from pathlib import Path

import numpy as np

from app.core.defense.rl.actions import ACTION_ORDER
from app.core.defense.rl.features import (
    SESSION_FEATURE_NAMES,
    SESSION_FEATURE_VERSION,
    SessionSnapshot,
    build_session_features,
)
from app.db.models import SessionAction

DEFAULT_WEIGHTS_PATH = Path(__file__).with_name("dqn_policy.npz")
MAX_MEMBERS = 15


class DQNPolicy:
    name = "dqn"

    def __init__(self, layers: list[tuple[np.ndarray, np.ndarray]]):
        if not layers:
            raise ValueError("need at least one layer")
        n_in = len(SESSION_FEATURE_NAMES)
        for weight, bias in layers:
            if weight.ndim != 2 or bias.shape != (weight.shape[0],):
                raise ValueError("layer shapes don't match")
            if weight.shape[1] != n_in:
                raise ValueError("layer input size doesn't match the previous layer")
            if not (np.all(np.isfinite(weight)) and np.all(np.isfinite(bias))):
                raise ValueError("weights contain a non-finite value")
            n_in = weight.shape[0]
        if n_in != len(ACTION_ORDER):
            raise ValueError("output size doesn't match the action space")
        self.layers = layers

    @classmethod
    def load(cls, path: str | Path = DEFAULT_WEIGHTS_PATH) -> "DQNPolicy":
        policy = load_dqn(path)
        if not isinstance(policy, cls):
            raise ValueError("file holds an ensemble; use load_dqn")
        return policy

    def q_values(self, x: np.ndarray) -> np.ndarray:
        h = np.asarray(x, dtype=float)
        for i, (weight, bias) in enumerate(self.layers):
            h = weight @ h + bias
            if i < len(self.layers) - 1:
                h = np.maximum(h, 0.0)  # ReLU, SB3's default for DQN's MlpPolicy
        return h

    def decide(self, snapshot: SessionSnapshot) -> SessionAction:
        q = self.q_values(build_session_features(snapshot))
        return ACTION_ORDER[int(np.argmax(q))]


class DQNEnsemble:
    """Independently trained Q-networks that vote: each member picks its
    greedy action, and the most picked action wins. A tie goes to the tied
    action with the highest Q-value summed over all members, so the result
    is deterministic. One badly trained member can't decide on its own."""

    name = "dqn"

    def __init__(self, members: list[DQNPolicy]):
        if not 1 <= len(members) <= MAX_MEMBERS:
            raise ValueError(f"an ensemble needs 1-{MAX_MEMBERS} members")
        self.members = members

    def decide(self, snapshot: SessionSnapshot) -> SessionAction:
        x = build_session_features(snapshot)
        q = np.stack([m.q_values(x) for m in self.members])
        votes = Counter(int(np.argmax(row)) for row in q)
        top = max(votes.values())
        tied = [a for a, n in votes.items() if n == top]
        q_sum = q.sum(axis=0)
        return ACTION_ORDER[max(tied, key=lambda a: q_sum[a])]


def _header() -> dict[str, np.ndarray]:
    return {
        "feature_version": np.array(SESSION_FEATURE_VERSION),
        "feature_names": np.array(SESSION_FEATURE_NAMES),
        "actions": np.array([a.value for a in ACTION_ORDER]),
    }


def _layer_arrays(prefix: str, layers: list[tuple[np.ndarray, np.ndarray]]) -> dict:
    arrays = {f"{prefix}n_layers": np.array(len(layers))}
    for i, (weight, bias) in enumerate(layers):
        arrays[f"{prefix}W{i}"] = np.asarray(weight, dtype=np.float32)
        arrays[f"{prefix}b{i}"] = np.asarray(bias, dtype=np.float32)
    return arrays


def save_weights(path: str | Path, layers: list[tuple[np.ndarray, np.ndarray]]) -> None:
    np.savez(Path(path), **_header(), **_layer_arrays("", layers))


def save_ensemble(path: str | Path, members: list[list[tuple[np.ndarray, np.ndarray]]]) -> None:
    arrays = {**_header(), "n_members": np.array(len(members))}
    for k, layers in enumerate(members):
        arrays.update(_layer_arrays(f"m{k}_", layers))
    np.savez(Path(path), **arrays)


def load_dqn(path: str | Path = DEFAULT_WEIGHTS_PATH) -> DQNPolicy | DQNEnsemble:
    """A single network or an ensemble, whichever the file holds."""
    with np.load(Path(path), allow_pickle=False) as data:
        if int(data["feature_version"]) != SESSION_FEATURE_VERSION:
            raise ValueError("DQN weights were trained on a different feature version")
        if tuple(str(n) for n in data["feature_names"]) != SESSION_FEATURE_NAMES:
            raise ValueError("DQN weights were trained on a different feature layout")
        if tuple(str(a) for a in data["actions"]) != tuple(a.value for a in ACTION_ORDER):
            raise ValueError("DQN weights were trained with a different action order")

        def layers(prefix: str) -> list[tuple[np.ndarray, np.ndarray]]:
            return [
                (
                    np.asarray(data[f"{prefix}W{i}"], dtype=float),
                    np.asarray(data[f"{prefix}b{i}"], dtype=float),
                )
                for i in range(int(data[f"{prefix}n_layers"]))
            ]

        if "n_members" not in data.files:
            return DQNPolicy(layers(""))
        n_members = int(data["n_members"])
        if not 1 <= n_members <= MAX_MEMBERS:
            raise ValueError(f"an ensemble needs 1-{MAX_MEMBERS} members")
        return DQNEnsemble([DQNPolicy(layers(f"m{k}_")) for k in range(n_members)])
