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

Optional mixed attack rate (third run): every `rate_block` episodes the
attack-session rate is redrawn uniformly from `rate_range`, so the agent
trains on quiet periods and attack waves instead of one fixed prior. The
agent can't observe the current rate; it sees only the session.
"""

from dataclasses import replace

import generate_sessions  # noqa: F401 - sets up the gateway import path
import gymnasium as gym
import numpy as np

from app.core.defense.rl.actions import ACTION_ORDER
from app.core.defense.rl.features import N_SESSION_FEATURES
from app.core.defense.rl.simulator import SessionSimulator


class SessionEnv(gym.Env):
    metadata = {"render_modes": []}

    def __init__(
        self,
        simulator: SessionSimulator,
        rate_range: tuple[float, float] | None = None,
        rate_block: int = 50,
    ):
        super().__init__()
        self.sim = simulator
        if rate_range is not None and not 0.0 <= rate_range[0] <= rate_range[1] <= 1.0:
            raise ValueError("rate_range must be 0 <= low <= high <= 1")
        self.rate_range = rate_range
        self.rate_block = rate_block
        self._episodes = 0
        # Attack-session rate used for each finished episode (mixed mode).
        self.episode_rates: list[float] = []
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
        if self.rate_range is not None and self._episodes % self.rate_block == 0:
            rate = float(self.np_random.uniform(*self.rate_range))
            self.sim.config = replace(self.sim.config, attack_session_rate=rate)
        self._episodes += 1
        # Episode randomness comes from the simulator's own generator,
        # reseeded from gymnasium's so seeding stays reproducible.
        obs, info = self.sim.reset(seed=int(self.np_random.integers(2**31)))
        return obs.astype(np.float32), info

    def step(self, action):
        obs, reward, terminated, truncated, info = self.sim.step(int(action))
        if terminated:
            self.episode_returns.append(info["episode"].env_return)
            self.episode_rates.append(self.sim.config.attack_session_rate)
        return obs.astype(np.float32), float(reward), terminated, truncated, info
