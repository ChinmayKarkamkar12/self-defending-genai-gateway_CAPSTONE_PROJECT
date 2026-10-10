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

**Best-checkpoint selection on validation** (added for the second run,
after the first evaluation found 2 of 5 unshaped agents had collapsed):
every VALIDATE_EVERY steps the current Q-network is played on
VALIDATION_SESSIONS validation sessions - val prompts, session seeds far
from anything training draws, shaping off - and the exported agent is the
best checkpoint by validation return *among those that respect the
go/no-go's safety limit* (benign lockout no more than the rule's + 1
point, measured on the same sessions). If no checkpoint qualifies the last
one is exported and flagged. Test sessions are never touched here.
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
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.utils import set_random_seed

from app.core.defense.rl.dqn import DQNPolicy, save_weights
from app.core.defense.rl.fallback_policy import RuleBasedPolicy
from app.core.defense.rl.simulator import run_episode

OUTPUT_DIR = gs.REPO_ROOT / "training" / "checkpoints" / "rl_agent"
SHAPING_COEF = 0.5
VALIDATE_EVERY = 25_000
VALIDATION_SESSIONS = 600
VALIDATION_SEED_OFFSET = 20_000_000  # apart from evaluate_rl_agent.py's 10M
LOCKOUT_SLACK = 0.01  # the go/no-go's safety limit

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


def validate(decide) -> dict[str, float]:
    """Return and benign lockout rate on the validation sessions."""
    sim = gs.simulator(gs.TRAIN_SPLIT, replace(gs.TRAIN, shaping_coef=0.0))
    stats = [
        run_episode(sim, decide, VALIDATION_SEED_OFFSET + i) for i in range(VALIDATION_SESSIONS)
    ]
    benign = [s for s in stats if s.label.value == "benign"]
    return {
        "return": float(np.mean([s.env_return for s in stats])),
        "benign_lockout": sum(s.locked_out for s in benign) / max(len(benign), 1),
    }


class BestOnValidation(BaseCallback):
    def __init__(self, lockout_limit: float):
        super().__init__()
        self.lockout_limit = lockout_limit
        self.best: tuple[float, int, list] | None = None
        self.history: list[dict] = []

    def _on_step(self) -> bool:
        if self.num_timesteps % VALIDATE_EVERY == 0:
            layers = export_q_network(self.model)
            result = validate(DQNPolicy(layers).decide)
            admissible = result["benign_lockout"] <= self.lockout_limit
            self.history.append({"step": self.num_timesteps, "admissible": admissible, **result})
            if admissible and (self.best is None or result["return"] > self.best[0]):
                self.best = (result["return"], self.num_timesteps, layers)
        return True


def train(seed: int, shaping: bool, timesteps: int) -> Path:
    set_random_seed(seed)
    config = replace(gs.TRAIN, shaping_coef=SHAPING_COEF if shaping else 0.0)
    env = SessionEnv(gs.simulator(gs.TRAIN_SPLIT, config, seed=seed))
    model = DQN("MlpPolicy", env, seed=seed, device="cpu", verbose=0, **HYPERPARAMETERS)
    rule_lockout = validate(RuleBasedPolicy().decide)["benign_lockout"]
    callback = BestOnValidation(rule_lockout + LOCKOUT_SLACK)

    started = time.time()
    model.learn(total_timesteps=timesteps, progress_bar=False, callback=callback)
    name = f"dqn_{'shaping' if shaping else 'noshaping'}_seed{seed}"
    path = OUTPUT_DIR / f"{name}.npz"
    if callback.best is not None:
        _, best_step, layers = callback.best
    else:
        best_step, layers = None, export_q_network(model)
    save_weights(path, layers)

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
                "validation": callback.history,
                "rule_validation_lockout": rule_lockout,
                # None = no checkpoint met the lockout limit; the final one
                # was exported.
                "selected_step": best_step,
            }
        )
    )
    print(
        f"{name}: {time.time() - started:.0f}s, {len(returns)} episodes, "
        f"selected step {best_step}"
    )
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    parser.add_argument("--timesteps", type=int, default=300_000)
    # Shaping on by default: the first run's ablation showed it is what
    # keeps training stable (0/5 collapses vs 2/5 without).
    parser.add_argument("--shaping", choices=["on", "off", "both"], default="on")
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for shaping in {"on": [True], "off": [False], "both": [True, False]}[args.shaping]:
        for seed in args.seeds:
            train(seed, shaping, args.timesteps)


if __name__ == "__main__":
    main()
