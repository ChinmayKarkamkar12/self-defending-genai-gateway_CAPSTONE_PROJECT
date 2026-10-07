"""LinUCB contextual bandit for the per-request defense decision. See
project_plan/06a-adaptive-defense-bandit.md §3.

Disjoint LinUCB (Li et al., 2010): each action ("arm") keeps its own ridge
regression of reward on the context vector x.

    A_a = ridge * I + sum of x x^T over the times arm a was rewarded
    b_a = sum of reward * x over the same times
    theta_a = A_a^-1 b_a                      (estimated reward weights)
    mean_a  = theta_a . x                     (expected reward of a, here)
    width_a = sqrt(x^T A_a^-1 x)              (uncertainty of that estimate)
    score_a = mean_a + alpha * width_a + escalation_bias * BIAS_DIRECTION[a]

The arm with the highest score is chosen. The `alpha * width` term is the
exploration: an arm that has rarely been tried in contexts like this one
has a wide confidence bound and gets tried, so its estimate can improve.
`width` shrinks as feedback arrives, which is what the dashboard can show.

This is a contextual *bandit*, not reinforcement learning: one context in,
one action out, one reward back, and the action doesn't change any future
state. The sequential, session-level problem is module 6b's (DQN).

Two policy overlays sit on top of the learned scores:

- **Masking**: an arm can be removed from consideration for one decision.
  The gateway stage masks `allow` above BANDIT_ALLOW_MASK_THRESHOLD so no
  amount of exploration lets a near-certain attack straight through.
- **escalation_bias**: module 6b's one-way hook. A positive bias tilts the
  choice toward the stricter arms for every request in a session, a
  negative one toward the more permissive arms. It shifts scores only; it
  never changes what the bandit has learned.

Warm start: a fresh bandit knows nothing, and exploring from scratch on
live traffic would block or allow requests at random. `apply_calibrated_prior`
seeds every arm with pseudo-observations of what each action would earn if
the classifier's probabilities were calibrated (reward.expected_reward).
Real feedback then corrects that prior where the classifier is wrong.
"""
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.core.defense.features import N_FEATURES, FeatureInputs, attack_probability, build_features
from app.core.defense.reward import expected_reward
from app.db.models import DefenseAction

ACTIONS: tuple[DefenseAction, ...] = (
    DefenseAction.ALLOW,
    DefenseAction.REDACT_AND_ALLOW,
    DefenseAction.BLOCK,
    DefenseAction.ESCALATE_TO_HUMAN,
)

# How escalation_bias moves each arm's score, in strictness order
# allow < redact < escalate < block. At the bias limit (+-1) the gap between
# allow and block moves by 1.0 - enough to flip borderline requests, not
# enough to block a clearly benign one (whose allow/block gap is ~1.3).
BIAS_DIRECTION: dict[DefenseAction, float] = {
    DefenseAction.ALLOW: -0.5,
    DefenseAction.REDACT_AND_ALLOW: -0.25,
    DefenseAction.ESCALATE_TO_HUMAN: 0.25,
    DefenseAction.BLOCK: 0.5,
}
MAX_ABS_BIAS = 1.0

STATE_FORMAT = 1
_TIE_TOLERANCE = 1e-9


@dataclass(frozen=True)
class ArmScore:
    mean: float
    width: float
    score: float
    masked: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "mean": self.mean,
            "width": self.width,
            "score": None if self.masked else self.score,
            "masked": self.masked,
        }


@dataclass(frozen=True)
class Selection:
    action: DefenseAction
    # 1 / (1 + width) of the chosen arm: 1.0 means the estimate is backed by
    # a lot of feedback in contexts like this one, values near 0 mean it is
    # mostly a guess. Stored as ThreatEvent.bandit_confidence.
    confidence: float
    arms: dict[DefenseAction, ArmScore]

    def arms_as_dict(self) -> dict[str, dict[str, Any]]:
        return {action.value: arm.as_dict() for action, arm in self.arms.items()}


def safety_mask(p_attack: float, allow_mask_threshold: float) -> frozenset[DefenseAction]:
    """Arms ruled out for this request regardless of what was learned:
    `allow` once the classifier is at least `allow_mask_threshold` sure
    it's an attack."""
    if p_attack >= allow_mask_threshold:
        return frozenset({DefenseAction.ALLOW})
    return frozenset()


def _check_vector(x: np.ndarray, n_features: int) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    if x.shape != (n_features,):
        raise ValueError(f"expected a context vector of shape ({n_features},), got {x.shape}")
    if not np.all(np.isfinite(x)):
        raise ValueError("context vector contains a non-finite value")
    return x


class LinUCB:
    def __init__(
        self,
        n_features: int = N_FEATURES,
        alpha: float = 0.5,
        ridge: float = 1.0,
        seed: int | None = None,
    ):
        if ridge <= 0:
            raise ValueError("ridge must be positive")
        self.n_features = n_features
        self.alpha = alpha
        self.ridge = ridge
        self.A = np.stack([ridge * np.eye(n_features) for _ in ACTIONS])
        self.b = np.zeros((len(ACTIONS), n_features))
        self.update_counts = np.zeros(len(ACTIONS), dtype=int)
        # Only used to break exact ties (e.g. every arm of a fresh bandit
        # scores identically). Seeded, so selection is reproducible.
        self._rng = np.random.default_rng(seed)

    def _estimate(self, arm: int, x: np.ndarray) -> tuple[float, float]:
        a_inv_x = np.linalg.solve(self.A[arm], x)
        theta = np.linalg.solve(self.A[arm], self.b[arm])
        mean = float(theta @ x)
        width = float(np.sqrt(max(float(x @ a_inv_x), 0.0)))
        return mean, width

    def select(
        self,
        x: np.ndarray,
        *,
        alpha: float | None = None,
        escalation_bias: float = 0.0,
        masked: frozenset[DefenseAction] | set[DefenseAction] = frozenset(),
    ) -> Selection:
        x = _check_vector(x, self.n_features)
        alpha = self.alpha if alpha is None else alpha
        if not np.isfinite(escalation_bias):
            raise ValueError("escalation_bias must be finite")
        bias = max(-MAX_ABS_BIAS, min(MAX_ABS_BIAS, float(escalation_bias)))
        if all(action in masked for action in ACTIONS):
            raise ValueError("every action is masked")

        arms: dict[DefenseAction, ArmScore] = {}
        for i, action in enumerate(ACTIONS):
            mean, width = self._estimate(i, x)
            score = mean + alpha * width + bias * BIAS_DIRECTION[action]
            arms[action] = ArmScore(mean=mean, width=width, score=score, masked=action in masked)

        candidates = [a for a in ACTIONS if not arms[a].masked]
        best_score = max(arms[a].score for a in candidates)
        tied = [a for a in candidates if arms[a].score >= best_score - _TIE_TOLERANCE]
        action = tied[0] if len(tied) == 1 else tied[int(self._rng.integers(len(tied)))]

        return Selection(
            action=action,
            confidence=1.0 / (1.0 + arms[action].width),
            arms=arms,
        )

    def update(
        self, x: np.ndarray, action: DefenseAction | str, reward: float, weight: float = 1.0
    ) -> None:
        """Fold one observed (context, action, reward) into the chosen arm.
        Only that arm learns - the other arms' rewards weren't observed."""
        x = _check_vector(x, self.n_features)
        if not np.isfinite(reward) or not np.isfinite(weight) or weight <= 0:
            raise ValueError("reward and weight must be finite, weight positive")
        arm = ACTIONS.index(DefenseAction(action))
        self.A[arm] += weight * np.outer(x, x)
        self.b[arm] += weight * reward * x
        self.update_counts[arm] += 1

    def to_state(self) -> dict[str, Any]:
        return {
            "format": STATE_FORMAT,
            "n_features": self.n_features,
            "ridge": self.ridge,
            "actions": [a.value for a in ACTIONS],
            "A": self.A.tolist(),
            "b": self.b.tolist(),
            "update_counts": self.update_counts.tolist(),
        }

    @classmethod
    def from_state(cls, state: dict[str, Any], alpha: float = 0.5) -> "LinUCB":
        if state.get("format") != STATE_FORMAT:
            raise ValueError("unsupported bandit state format")
        if state.get("actions") != [a.value for a in ACTIONS]:
            raise ValueError("bandit state was saved with a different action set")
        if state.get("n_features") != N_FEATURES:
            raise ValueError("bandit state was saved with a different feature layout")
        bandit = cls(n_features=state["n_features"], alpha=alpha, ridge=state["ridge"])
        a = np.asarray(state["A"], dtype=float)
        b = np.asarray(state["b"], dtype=float)
        if a.shape != bandit.A.shape or b.shape != bandit.b.shape:
            raise ValueError("bandit state has the wrong shape")
        if not (np.all(np.isfinite(a)) and np.all(np.isfinite(b))):
            raise ValueError("bandit state contains a non-finite value")
        bandit.A, bandit.b = a, b
        bandit.update_counts = np.asarray(state["update_counts"], dtype=int)
        return bandit


# Prior strength: PRIOR_CONTEXTS synthetic contexts per arm, each counted
# PRIOR_WEIGHT times - worth ~50 real observations per arm, so a few dozen
# consistent pieces of real feedback visibly move the policy.
PRIOR_CONTEXTS = 200
PRIOR_WEIGHT = 0.25
PRIOR_SEED = 0


def _prior_inputs(rng: np.random.Generator) -> FeatureInputs:
    # Mirrors the classifier's saturated outputs: most scores sit near 0 or
    # 1, with a uniform band so the middle of the range is covered too.
    kind = rng.random()
    if kind < 0.4:
        p_attack = float(rng.uniform(0.0, 1.0))
    elif kind < 0.7:
        p_attack = float(rng.beta(0.3, 8.0))
    else:
        p_attack = float(1.0 - rng.beta(0.3, 8.0))
    injection_share = float(rng.uniform(0.0, 1.0))
    has_system = rng.random() < 0.5
    system_attack = float(rng.beta(0.5, 5.0))
    return FeatureInputs(
        threat_score={
            "benign": 1.0 - p_attack,
            "prompt_injection": p_attack * injection_share,
            "jailbreak": p_attack * (1.0 - injection_share),
        },
        system_prompt_threat_score=(
            {
                "benign": 1.0 - system_attack,
                "prompt_injection": system_attack,
                "jailbreak": 0.0,
            }
            if has_system
            else None
        ),
        scan_windows=int(rng.integers(1, 9)),
        scan_truncated=bool(rng.random() < 0.02),
        pii_entity_count=int(rng.integers(0, 4)),
        hour_utc=float(rng.uniform(0.0, 24.0)),
        team_requests_this_minute=int(rng.integers(1, 31)),
    )


def apply_calibrated_prior(
    bandit: LinUCB,
    n_contexts: int = PRIOR_CONTEXTS,
    weight: float = PRIOR_WEIGHT,
    seed: int = PRIOR_SEED,
) -> LinUCB:
    """Seed every arm with the reward it would earn if the classifier's
    attack probability were calibrated. Deterministic for a given seed.
    Doesn't count towards `update_counts` - those track real feedback only."""
    rng = np.random.default_rng(seed)
    for _ in range(n_contexts):
        inputs = _prior_inputs(rng)
        x = build_features(inputs)
        p_attack = attack_probability(inputs.threat_score)
        for action in ACTIONS:
            bandit.update(x, action, expected_reward(action, p_attack), weight=weight)
    bandit.update_counts[:] = 0
    return bandit


def new_bandit(alpha: float = 0.5, seed: int | None = None) -> LinUCB:
    """A warm-started bandit - what the gateway runs before any feedback."""
    return apply_calibrated_prior(LinUCB(alpha=alpha, seed=seed))
