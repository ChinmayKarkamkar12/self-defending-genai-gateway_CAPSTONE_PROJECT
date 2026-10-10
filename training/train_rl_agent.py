"""Train the session agent's DQN with stable-baselines3 (module 6b). See
project_plan/06b-adaptive-defense-rl-session-agent.md §4.

Run from the repo root with the project venv (after
`pip install -r training/requirements.txt`, which adds stable-baselines3
and gymnasium; training/data/bandit_scores_val.jsonl must exist - see
generate_sessions.py):

    gateway/.venv/Scripts/python.exe training/train_rl_agent.py

Trains one agent per (seed, shaping) pair against simulated sessions built
from the **val** split's prompts, then exports each Q-network to
training/checkpoints/rl_agent/dqn_<shaping|noshaping>_seed<k>.npz - plain
arrays the gateway runs with numpy (app/core/defense/rl/dqn.py). The SB3
model itself is not kept: loading one unpickles code.

Several seeds because DQN results vary a lot between runs; the evaluation
reports all of them rather than the best. Shaping on/off is the plan's
ablation (rl/reward.py explains the shaping term).

Hyperparameters: a 64-64 MLP (the plan's "2-3 hidden layers, 64-128
units" - the state has 14 features and there are 5 actions). Sessions are
at most 15 steps, so gamma = 0.99 makes the terminal reward count almost in
full at every step. Exploration anneals from 1.0 to 0.05 over the first
30% of training. Not tuned beyond checking that training curves level off
(L6b-6).
"""

import argparse
import json
import time
from dataclasses import replace
from pathlib import Path

import generate_sessions as gs
import numpy as np
import torch
from rl_env import SessionEnv
from stable_baselines3 import DQN
from stable_baselines3.common.utils import set_random_seed

from app.core.defense.rl.dqn import save_weights

OUTPUT_DIR = gs.REPO_ROOT / "training" / "checkpoints" / "rl_agent"
SHAPING_COEF = 0.5

HYPERPARAMETERS = dict(
    learning_rate=5e-4,
    buffer_size=100_000,
    learning_starts=2_000,
    batch_size=128,
    gamma=0.99,
    train_freq=4,
    gradient_steps=1,
    target_update_interval=2_000,
    exploration_fraction=0.3,
    exploration_initial_eps=1.0,
    exploration_final_eps=0.05,
    policy_kwargs=dict(net_arch=[64, 64]),
)


def export_q_network(model: DQN) -> list[tuple[np.ndarray, np.ndarray]]:
    """The online Q-network's Linear layers, in order. SB3's MlpPolicy for
    DQN is Flatten -> [Linear, ReLU]* -> Linear, which dqn.DQNPolicy
    reproduces."""
    layers = [
        (m.weight.detach().cpu().numpy(), m.bias.detach().cpu().numpy())
        for m in model.q_net.q_net
        if isinstance(m, torch.nn.Linear)
    ]
    activations = [m for m in model.q_net.q_net if not isinstance(m, torch.nn.Linear)]
    if not all(isinstance(m, torch.nn.ReLU) for m in activations):
        raise RuntimeError("unexpected activation in the Q-network; dqn.py assumes ReLU")
    return layers


def train(seed: int, shaping: bool, timesteps: int) -> Path:
    set_random_seed(seed)
    config = replace(gs.TRAIN, shaping_coef=SHAPING_COEF if shaping else 0.0)
    env = SessionEnv(gs.simulator(gs.TRAIN_SPLIT, config, seed=seed))
    model = DQN("MlpPolicy", env, seed=seed, device="cpu", verbose=0, **HYPERPARAMETERS)

    started = time.time()
    model.learn(total_timesteps=timesteps, progress_bar=False)
    name = f"dqn_{'shaping' if shaping else 'noshaping'}_seed{seed}"
    path = OUTPUT_DIR / f"{name}.npz"
    save_weights(path, export_q_network(model))

    # Episode returns over training (env reward, shaping excluded), for
    # the learning-curve check.
    returns = env.episode_returns
    (OUTPUT_DIR / f"{name}.json").write_text(
        json.dumps(
            {
                "seed": seed,
                "shaping": shaping,
                "timesteps": timesteps,
                "seconds": round(time.time() - started, 1),
                "hyperparameters": {k: str(v) for k, v in HYPERPARAMETERS.items()},
                "episode_returns": returns,
            }
        )
    )
    print(f"{name}: {time.time() - started:.0f}s, {len(returns)} episodes")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    parser.add_argument("--timesteps", type=int, default=150_000)
    parser.add_argument("--shaping", choices=["on", "off", "both"], default="both")
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for shaping in {"on": [True], "off": [False], "both": [True, False]}[args.shaping]:
        for seed in args.seeds:
            train(seed, shaping, args.timesteps)


if __name__ == "__main__":
    main()
