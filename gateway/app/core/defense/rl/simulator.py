"""Session simulator: the training and evaluation environment for the
session agent. See project_plan/06b-adaptive-defense-rl-session-agent.md §3.

An untrained agent can't explore by locking out real users, so the agent
is trained and evaluated here, offline. The Gym-style interface is
reset() -> (obs, info) and step(action) -> (obs, reward, terminated,
truncated, info); training/rl_env.py wraps it as a gymnasium.Env for
stable-baselines3. It is plain numpy so CI can test it.

**Faithful to module 6a.** Each simulated request is decided by 6a's real
code: `build_features`, `safety_mask` and the warm-started `LinUCB.select`
with the session's current `escalation_bias` (`BanditDecider`). Nothing
about 6a is reimplemented here. The bandit is frozen at its warm-start
prior: what a fresh deployment runs. In production it keeps learning, so
the agent is trained against day-one 6a (L6b-4).

**Prompts are real.** Each request is a held-out prompt from module 5's
dataset with its cached production-classifier score (training/data/
bandit_scores_<split>.jsonl). Requests are drawn from those pools; only the
session structure around them is simulated.

**Session archetypes:**

- Benign: `length` benign prompts. A share of users (`fp_user_rate`) are
  "false-positive prone": each of their requests is, with probability
  `fp_request_rate`, given a score from `fp_band` (0.95-0.995 - the band
  where module 5's measured false positives sit, L5-2). This is the same
  labelled drift simulation as 6a's Experiment C.
- Attack: one to `max_probes` benign-looking probe requests, then attack
  attempts. The attacker *reacts* to what the gateway does - this is what
  makes the problem sequential:
    - an attack request that is allowed is a breach; the attacker got what
      they wanted and the session ends;
    - one that is refused (redact, block or escalate) is retried with
      probability `persistence` (a rephrased attempt), otherwise the
      attacker gives up;
    - each rephrased attempt is a fresh draw from the attack pool. Under
      the default `evasion_growth` = 0 that is the real score
      distribution, in which ~4% of attacks score below 0.2 (the
      classifier's blind spot), so a persistent attacker eventually gets
      one past 6a on scores alone. `evasion_growth` > 0 models an
      attacker who learns from refusals: after k refusals, a share
      min(1, k * evasion_growth) of attempts come from the low-scoring
      attacks (used for the shifted held-out evaluation).

**Timing.** The agent acts after each request (SESSION_POLICY_EVERY_N = 1,
the gateway default) and its action applies from the next request on.
reset() processes the first request with a neutral bias.

**Simplifications** (L6b-3): a redact on an attack counts as neutralised
(the gateway would re-scan and maybe block - text isn't available here);
the per-team review cap is ignored; a lockout refuses all of the session's
remaining requests (each counted as a block of a request with the session's
label); benign users don't react to refusals.
"""
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace

import numpy as np

from app.core.defense.bandit import LinUCB, new_bandit, safety_mask
from app.core.defense.features import FeatureInputs, attack_probability, build_features
from app.core.defense.rl.actions import ACTION_ORDER, INTERVENTIONS, guard, next_bias
from app.core.defense.rl.features import RECENT_WINDOW, SessionSnapshot, build_session_features
from app.core.defense.rl.reward import potential, request_reward, shaping, terminal_reward
from app.db.models import DefenseAction, SessionAction, ThreatLabel


@dataclass(frozen=True)
class ScoredPrompt:
    """One held-out prompt as module 5 scored it. No text."""

    threat_score: dict[str, float]
    is_attack: bool
    windows: int = 1
    truncated: bool = False

    @property
    def p_attack(self) -> float:
        return attack_probability(self.threat_score)


@dataclass(frozen=True)
class SimConfig:
    attack_session_rate: float = 0.5
    min_length: int = 3
    max_length: int = 15
    fp_user_rate: float = 0.2
    fp_request_rate: float = 0.3
    fp_band: tuple[float, float] = (0.95, 0.995)
    min_probes: int = 1
    max_probes: int = 3
    persistence: float = 0.85
    evasion_growth: float = 0.0
    evasion_threshold: float = 0.2
    # Share of requests in which module 4 finds PII. The dataset has no PII
    # labels; this is drawn independently of the session's label, so the
    # agent can't learn to read anything into it.
    pii_request_rate: float = 0.15
    shaping_coef: float = 0.0
    gamma: float = 0.99

    def __post_init__(self):
        if not 1 <= self.min_length <= self.max_length:
            raise ValueError("need 1 <= min_length <= max_length")
        if not 0 <= self.min_probes <= self.max_probes:
            raise ValueError("need 0 <= min_probes <= max_probes")


class BanditDecider:
    """Module 6a's per-request decision, called through its real code.

    Memoised: the bandit is frozen, so the outcome depends only on the
    request's features, the bias and the masks. Ties (only possible in
    exactly symmetric states, never with the warm-start prior) would be
    broken by the bandit's seeded RNG.
    """

    def __init__(
        self,
        bandit: LinUCB | None = None,
        *,
        alpha: float = 0.5,
        allow_mask_threshold: float = 0.99,
        redact_mask_threshold: float = 0.999,
    ):
        self.bandit = bandit if bandit is not None else new_bandit(alpha=alpha, seed=0)
        self.alpha = alpha
        self.allow_mask_threshold = allow_mask_threshold
        self.redact_mask_threshold = redact_mask_threshold
        self._cache: dict[tuple, DefenseAction] = {}

    def decide(self, prompt: ScoredPrompt, pii_entities: int, bias: float) -> DefenseAction:
        key = (
            tuple(sorted(prompt.threat_score.items())),
            prompt.windows,
            prompt.truncated,
            pii_entities,
            round(bias, 9),
        )
        action = self._cache.get(key)
        if action is None:
            x = build_features(
                FeatureInputs(
                    threat_score=prompt.threat_score,
                    scan_windows=prompt.windows,
                    scan_truncated=prompt.truncated,
                    pii_entity_count=pii_entities,
                )
            )
            masked = safety_mask(
                prompt.p_attack, self.allow_mask_threshold, self.redact_mask_threshold
            )
            action = self.bandit.select(
                x, alpha=self.alpha, escalation_bias=bias, masked=masked
            ).action
            self._cache[key] = action
        return action


@dataclass
class _Tracker:
    """The in-memory equivalent of the gateway's Redis session state."""

    request_count: int = 0
    outcome_counts: dict[str, int] = field(default_factory=dict)
    consecutive_refused: int = 0
    recent_scores: list[float] = field(default_factory=list)
    pii_requests: int = 0

    def record(self, outcome: DefenseAction, p_attack: float, pii: bool) -> None:
        self.request_count += 1
        self.outcome_counts[outcome.value] = self.outcome_counts.get(outcome.value, 0) + 1
        self.consecutive_refused = (
            0 if outcome == DefenseAction.ALLOW else self.consecutive_refused + 1
        )
        self.recent_scores = (self.recent_scores + [p_attack])[-RECENT_WINDOW:]
        self.pii_requests += int(pii)

    def snapshot(self, bias: float, challenge_pending: bool) -> SessionSnapshot:
        return SessionSnapshot(
            request_count=self.request_count,
            outcome_counts=dict(self.outcome_counts),
            consecutive_refused=self.consecutive_refused,
            recent_scores=tuple(self.recent_scores),
            pii_requests=self.pii_requests,
            escalation_bias=bias,
            challenge_pending=challenge_pending,
        )


@dataclass
class EpisodeStats:
    """What happened in one session - read by the evaluation script."""

    label: ThreatLabel
    length: int
    requests: int = 0
    benign_requests: int = 0
    benign_refused: int = 0
    attack_requests: int = 0
    attack_refused: int = 0
    breached: bool = False
    gave_up: bool = False
    locked_out: bool = False
    locked_out_requests: int = 0
    intervened: bool = False
    actions: list[str] = field(default_factory=list)
    env_return: float = 0.0


class SessionSimulator:
    def __init__(
        self,
        benign_pool: Sequence[ScoredPrompt],
        attack_pool: Sequence[ScoredPrompt],
        config: SimConfig | None = None,
        decider: BanditDecider | None = None,
        seed: int | None = None,
    ):
        if not benign_pool or not attack_pool:
            raise ValueError("need non-empty benign and attack pools")
        self.config = config or SimConfig()
        self.benign_pool = list(benign_pool)
        self.attack_pool = list(attack_pool)
        self.low_attacks = [
            p for p in self.attack_pool if p.p_attack < self.config.evasion_threshold
        ]
        self.decider = decider or BanditDecider()
        self.rng = np.random.default_rng(seed)
        self._done = True

    # ------------------------------------------------------------ session

    def _draw(self, pool: Sequence[ScoredPrompt]) -> ScoredPrompt:
        return pool[int(self.rng.integers(len(pool)))]

    def _next_prompt(self) -> ScoredPrompt:
        cfg = self.config
        if self.stats.label == ThreatLabel.BENIGN:
            prompt = self._draw(self.benign_pool)
            if self._fp_user and self.rng.random() < cfg.fp_request_rate:
                p = float(self.rng.uniform(*cfg.fp_band))
                prompt = replace(
                    prompt,
                    threat_score={"benign": 1.0 - p, "prompt_injection": p, "jailbreak": 0.0},
                )
            return prompt
        if self._probes_left > 0:
            self._probes_left -= 1
            return self._draw(self.benign_pool)
        evasion = min(1.0, cfg.evasion_growth * self.stats.attack_refused)
        if self.low_attacks and evasion > 0 and self.rng.random() < evasion:
            return self._draw(self.low_attacks)
        return self._draw(self.attack_pool)

    def _process_request(self) -> float:
        """Send the session's next request through 6a. Returns its request
        reward and updates the episode's end conditions."""
        cfg = self.config
        prompt = self._next_prompt()
        pii = int(self.rng.integers(1, 4)) if self.rng.random() < cfg.pii_request_rate else 0
        if self._challenge_pending:
            outcome = DefenseAction.ESCALATE_TO_HUMAN
            self._challenge_pending = False
        else:
            outcome = self.decider.decide(prompt, pii, self._bias)
        self._tracker.record(outcome, prompt.p_attack, pii > 0)

        s = self.stats
        s.requests += 1
        refused = outcome != DefenseAction.ALLOW
        if prompt.is_attack:
            s.attack_requests += 1
            if not refused:
                s.breached = True
                self._done = True
            else:
                s.attack_refused += 1
                if self.rng.random() >= cfg.persistence:
                    s.gave_up = True
                    self._done = True
        else:
            s.benign_requests += 1
            s.benign_refused += int(refused)
        if s.requests >= s.length:
            self._done = True
        return request_reward(outcome, prompt.is_attack)

    # ---------------------------------------------------------------- api

    def snapshot(self) -> SessionSnapshot:
        return self._tracker.snapshot(self._bias, self._challenge_pending)

    def observation(self) -> np.ndarray:
        return build_session_features(self.snapshot())

    def reset(self, seed: int | None = None) -> tuple[np.ndarray, dict]:
        if seed is not None:
            self.rng = np.random.default_rng(seed)
        cfg = self.config
        while True:
            is_attack = self.rng.random() < cfg.attack_session_rate
            label = ThreatLabel.ATTACK if is_attack else ThreatLabel.BENIGN
            length = int(self.rng.integers(cfg.min_length, cfg.max_length + 1))
            self.stats = EpisodeStats(label=label, length=length)
            self._fp_user = (not is_attack) and self.rng.random() < cfg.fp_user_rate
            self._probes_left = (
                int(self.rng.integers(cfg.min_probes, cfg.max_probes + 1)) if is_attack else 0
            )
            self._tracker = _Tracker()
            self._bias = 0.0
            self._challenge_pending = False
            self._done = False
            self._process_request()
            if not self._done:
                break
            # A session over after one request (an attack allowed on the
            # very first try, or a length-1 session) gives the agent no
            # decision to make; draw another.
        return self.observation(), {"label": label.value}

    def step(self, action: int | SessionAction) -> tuple[np.ndarray, float, bool, bool, dict]:
        if self._done:
            raise RuntimeError("episode is over; call reset()")
        cfg = self.config
        chosen = ACTION_ORDER[action] if isinstance(action, int | np.integer) else action
        before = self.snapshot()
        taken = guard(SessionAction(chosen), before)
        self.stats.actions.append(taken.value)
        if taken in INTERVENTIONS:
            self.stats.intervened = True

        reward = 0.0
        if taken == SessionAction.LOCKOUT:
            s = self.stats
            remaining = max(s.length - s.requests, 0)
            s.locked_out = True
            s.locked_out_requests = remaining
            is_attack = s.label == ThreatLabel.ATTACK
            reward += remaining * request_reward(DefenseAction.BLOCK, is_attack)
            if not is_attack:
                s.benign_refused += remaining
                s.benign_requests += remaining
            self._done = True
        else:
            self._bias = next_bias(self._bias, taken)
            if taken == SessionAction.CHALLENGE:
                self._challenge_pending = True
            reward += self._process_request()

        after = self.snapshot()
        if self._done:
            reward += terminal_reward(self.stats.label, self.stats.intervened, self.stats.breached)
        self.stats.env_return += reward
        reward += shaping(
            potential(before),
            potential(after),
            coef=cfg.shaping_coef,
            gamma=cfg.gamma,
            terminal=self._done,
        )
        info = {"label": self.stats.label.value, "taken": taken.value}
        if self._done:
            info["episode"] = self.stats
        return build_session_features(after), reward, self._done, False, info


SessionPolicyFn = Callable[[SessionSnapshot], SessionAction]


def run_episode(sim: SessionSimulator, decide: SessionPolicyFn, seed: int) -> EpisodeStats:
    """Play one session with a policy that reads snapshots (rule-based,
    maintain-only, or the DQN through dqn.DQNPolicy.decide)."""
    sim.reset(seed=seed)
    done = False
    while not done:
        _, _, done, _, _ = sim.step(decide(sim.snapshot()))
    return sim.stats
