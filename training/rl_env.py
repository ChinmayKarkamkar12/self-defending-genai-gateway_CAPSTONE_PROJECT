"""Gym-style environment for the session agent (module 6b). See
project_plan/06b-adaptive-defense-rl-session-agent.md §3.

A thin gymnasium.Env around gateway/app/core/defense/rl/simulator.py, which
holds all of the logic (state, actions, reward, the attacker model, calls
into module 6a's real decision code) so the gateway's CI tests can cover it
without gymnasium installed. This wrapper only adds the spaces
stable-baselines3 needs.

    observation: the 14-feature session vector (rl/features.py)
    action:      Discrete(5), index into rl/actions.ACTION_ORDER
                 (maintain, tighten, relax, challenge, lockout)
"""

import generate_sessions  # noqa: F401 - sets up the gateway import path
import gymnasium as gym
import numpy as np

from app.core.defense.rl.actions import ACTION_ORDER
from app.core.defense.rl.features import N_SESSION_FEATURES
from app.core.defense.rl.simulator import SessionSimulator


class SessionEnv(gym.Env):
    metadata = {"render_modes": []}

    def __init__(self, simulator: SessionSimulator):
        super().__init__()
        self.sim = simulator
        # Bias in [-0.3, 1], slope in [-1, 1], everything else in [0, 1].
        self.observation_space = gym.spaces.Box(
            low=-1.0, high=1.0, shape=(N_SESSION_FEATURES,), dtype=np.float32
        )
        self.action_space = gym.spaces.Discrete(len(ACTION_ORDER))
        # Environment return (shaping excluded) of every finished episode:
        # the learning curve.
        self.episode_returns: list[float] = []

    def reset(self, *, seed: int | None = None, options: dict | None = None):
        super().reset(seed=seed)
        # Episode randomness comes from the simulator's own generator,
        # reseeded from gymnasium's so seeding stays reproducible.
        obs, info = self.sim.reset(seed=int(self.np_random.integers(2**31)))
        return obs.astype(np.float32), info

    def step(self, action):
        obs, reward, terminated, truncated, info = self.sim.step(int(action))
        if terminated:
            self.episode_returns.append(info["episode"].env_return)
        return obs.astype(np.float32), float(reward), terminated, truncated, info
