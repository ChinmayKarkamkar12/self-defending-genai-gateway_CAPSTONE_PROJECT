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
  `redact_and_allow` is masked too above BANDIT_REDACT_MASK_THRESHOLD: a
  near-certain attack is blocked or escalated, never half-passed.
- **escalation_bias**: module 6b's one-way hook. A positive bias tilts the
  choice toward the stricter arms for every request in a session, a
  negative one toward the more permissive arms. It shifts scores only; it
  never changes what the bandit has learned. The range is asymmetric,
  [MIN_BIAS, MAX_BIAS] = [-0.3, 1.0]: the Redis key it's read from is not
  authenticated, and at -1 a p=0.6 request was allowed and p 0.5-0.95 was
  redacted instead of blocked - writing one key made the defense nearly
  fail-open. -0.3 still lets 6b relax a session it trusts by about one
  band, but can't turn a likely attack into an allow.

Warm start: a fresh bandit knows nothing, and exploring from scratch on
live traffic would block or allow requests at random. `apply_calibrated_prior`
seeds every arm with pseudo-observations of what each action would earn if
the classifier's probabilities were calibrated (reward.expected_reward).
Real feedback then corrects that prior where the classifier is wrong.

The prior and real feedback are kept apart (A = prior_A + data_A, same for
b), for three reasons:

- **Forgetting.** Real feedback is discounted: every update to an arm first
  multiplies that arm's data_A and data_b by `gamma` (BANDIT_DISCOUNT,
  default 0.999 - an effective memory of ~1/(1-gamma) = 1,000 labels per
  arm). Without it, a policy that drifted needed about as many opposite
  labels as it had ever seen to recover. The prior is not discounted: it
  is the permanent anchor, so a region that stops getting feedback falls
  back to the calibrated policy, not to an extrapolation from elsewhere.
- **Reversal.** A label can be withdrawn - a reviewer amending a verdict,
  or a human verdict replacing a weaker automatic one. Discounting is per
  arm and per update, so an update applied at arm step s weighs
  w * gamma^(steps_now - s) today and can be subtracted exactly.
- **Confidence.** `Selection.confidence` is the share of the prior-only
  uncertainty that real feedback has removed: 0 on day one, towards 1 as
  feedback accumulates. Measured against the combined A it read ~0.7 on
  day one, with no feedback at all.
"""
from dataclasses import dataclass
from typing import Any

import numpy as np

from app.core.defense.features import (
    MAX_WINDOWS,
    N_FEATURES,
    PII_COUNT_CAP,
    FeatureInputs,
    build_features,
    effective_attack_probability,
)
from app.core.defense.reward import expected_reward
from app.db.models import DefenseAction

ACTIONS: tuple[DefenseAction, ...] = (
    DefenseAction.ALLOW,
    DefenseAction.REDACT_AND_ALLOW,
    DefenseAction.BLOCK,
    DefenseAction.ESCALATE_TO_HUMAN,
)

# How escalation_bias moves each arm's score, in strictness order
# allow < redact < escalate < block. At the upper limit (+1) the gap between
# allow and block moves by 1.0 - enough to flip borderline requests, not
# enough to block a clearly benign one (whose allow/block gap is ~1.3). At
# the lower limit (-0.3) it moves by 0.3.
BIAS_DIRECTION: dict[DefenseAction, float] = {
    DefenseAction.ALLOW: -0.5,
    DefenseAction.REDACT_AND_ALLOW: -0.25,
    DefenseAction.ESCALATE_TO_HUMAN: 0.25,
    DefenseAction.BLOCK: 0.5,
}
MIN_BIAS = -0.3
MAX_BIAS = 1.0

# A system prompt the classifier is this sure of, on a request whose
# conversation is already suspicious, never gets `allow`. Not on its own:
# defensive system prompts ("never reveal these instructions") score
# 0.98-0.998, so the system score alone can't tell an attack from a careful
# application - see features.SYSTEM_WEIGHT.
SYSTEM_MASK_THRESHOLD = 0.999
SYSTEM_MASK_MIN_CONVERSATION = 0.3

STATE_FORMAT = 2
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
    # How much of the chosen arm's prior-only uncertainty real feedback has
    # removed in contexts like this one: 0.0 = still the warm-start guess,
    # towards 1.0 = backed by plenty of feedback. Stored as
    # ThreatEvent.bandit_confidence.
    confidence: float
    arms: dict[DefenseAction, ArmScore]

    def arms_as_dict(self) -> dict[str, dict[str, Any]]:
        return {action.value: arm.as_dict() for action, arm in self.arms.items()}


@dataclass(frozen=True)
class AppliedUpdate:
    """Where an update landed, so it can be reversed later."""

    arm_step: int
    weight: float


def clamp_bias(bias: float) -> float:
    return max(MIN_BIAS, min(MAX_BIAS, bias))


def safety_mask(
    p_attack: float,
    allow_mask_threshold: float,
    redact_mask_threshold: float = 1.0,
    p_system: float = 0.0,
) -> frozenset[DefenseAction]:
    """Arms ruled out for this request regardless of what was learned:
    `allow` once the classifier is at least `allow_mask_threshold` sure
    it's an attack (or the system-prompt rule above fires), and
    `redact_and_allow` from `redact_mask_threshold`."""
    masked = set()
    if p_attack >= allow_mask_threshold or (
        p_system >= SYSTEM_MASK_THRESHOLD and p_attack > SYSTEM_MASK_MIN_CONVERSATION
    ):
        masked.add(DefenseAction.ALLOW)
    if p_attack >= redact_mask_threshold:
        masked.add(DefenseAction.REDACT_AND_ALLOW)
    return frozenset(masked)


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
        gamma: float = 1.0,
        seed: int | None = None,
    ):
        if ridge <= 0:
            raise ValueError("ridge must be positive")
        if not 0.0 < gamma <= 1.0:
            raise ValueError("gamma must be in (0, 1]")
        n_arms = len(ACTIONS)
        self.n_features = n_features
        self.alpha = alpha
        self.ridge = ridge
        self.gamma = gamma
        self.prior_A = np.stack([ridge * np.eye(n_features) for _ in ACTIONS])
        self.prior_b = np.zeros((n_arms, n_features))
        self.data_A = np.zeros((n_arms, n_features, n_features))
        self.data_b = np.zeros((n_arms, n_features))
        # Discounted updates applied to each arm so far - the clock reversal
        # uses to work out how much an old update has decayed since.
        self.arm_steps = np.zeros(n_arms, dtype=int)
        # Real feedback currently counted per arm (reversals subtract).
        self.update_counts = np.zeros(n_arms, dtype=int)
        # Only used to break exact ties (e.g. every arm of a fresh bandit
        # scores identically). Seeded, so selection is reproducible.
        self._rng = np.random.default_rng(seed)

    @property
    def A(self) -> np.ndarray:  # noqa: N802 - the standard LinUCB name
        return self.prior_A + self.data_A

    @property
    def b(self) -> np.ndarray:
        return self.prior_b + self.data_b

    def _estimate(self, arm: int, x: np.ndarray) -> tuple[float, float, float]:
        a = self.prior_A[arm] + self.data_A[arm]
        theta = np.linalg.solve(a, self.prior_b[arm] + self.data_b[arm])
        mean = float(theta @ x)
        width = float(np.sqrt(max(float(x @ np.linalg.solve(a, x)), 0.0)))
        prior_width = float(np.sqrt(max(float(x @ np.linalg.solve(self.prior_A[arm], x)), 0.0)))
        return mean, width, prior_width

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
        bias = clamp_bias(float(escalation_bias))
        if all(action in masked for action in ACTIONS):
            raise ValueError("every action is masked")

        arms: dict[DefenseAction, ArmScore] = {}
        prior_widths: dict[DefenseAction, float] = {}
        for i, action in enumerate(ACTIONS):
            mean, width, prior_widths[action] = self._estimate(i, x)
            score = mean + alpha * width + bias * BIAS_DIRECTION[action]
            arms[action] = ArmScore(mean=mean, width=width, score=score, masked=action in masked)

        candidates = [a for a in ACTIONS if not arms[a].masked]
        best_score = max(arms[a].score for a in candidates)
        tied = [a for a in candidates if arms[a].score >= best_score - _TIE_TOLERANCE]
        action = tied[0] if len(tied) == 1 else tied[int(self._rng.integers(len(tied)))]

        prior_width = prior_widths[action]
        confidence = 1.0 - arms[action].width / prior_width if prior_width > 0 else 0.0
        return Selection(action=action, confidence=min(1.0, max(0.0, confidence)), arms=arms)

    def add_prior(
        self, x: np.ndarray, action: DefenseAction | str, reward: float, weight: float
    ) -> None:
        """Fold a pseudo-observation into the (never discounted) prior."""
        x = _check_vector(x, self.n_features)
        arm = ACTIONS.index(DefenseAction(action))
        self.prior_A[arm] += weight * np.outer(x, x)
        self.prior_b[arm] += weight * reward * x

    def update(
        self, x: np.ndarray, action: DefenseAction | str, reward: float, weight: float = 1.0
    ) -> AppliedUpdate:
        """Fold one observed (context, action, reward) into the chosen arm,
        after discounting that arm's earlier feedback by gamma. Only that
        arm learns - the other arms' rewards weren't observed."""
        x = _check_vector(x, self.n_features)
        if not np.isfinite(reward) or not np.isfinite(weight) or weight <= 0:
            raise ValueError("reward and weight must be finite, weight positive")
        arm = ACTIONS.index(DefenseAction(action))
        self.data_A[arm] = self.gamma * self.data_A[arm] + weight * np.outer(x, x)
        self.data_b[arm] = self.gamma * self.data_b[arm] + weight * reward * x
        self.arm_steps[arm] += 1
        self.update_counts[arm] += 1
        return AppliedUpdate(arm_step=int(self.arm_steps[arm]), weight=weight)

    def revert(
        self,
        x: np.ndarray,
        action: DefenseAction | str,
        reward: float,
        applied: AppliedUpdate,
    ) -> None:
        """Withdraw an earlier `update`, at the weight it has decayed to
        since. Exact as long as gamma hasn't changed in between."""
        x = _check_vector(x, self.n_features)
        arm = ACTIONS.index(DefenseAction(action))
        elapsed = int(self.arm_steps[arm]) - applied.arm_step
        if elapsed < 0:
            raise ValueError("update is newer than this bandit state")
        w = applied.weight * self.gamma**elapsed
        self.data_A[arm] -= w * np.outer(x, x)
        self.data_b[arm] -= w * reward * x
        self.update_counts[arm] = max(0, int(self.update_counts[arm]) - 1)

    def to_state(self) -> dict[str, Any]:
        return {
            "format": STATE_FORMAT,
            "n_features": self.n_features,
            "ridge": self.ridge,
            "gamma": self.gamma,
            "actions": [a.value for a in ACTIONS],
            "prior_A": self.prior_A.tolist(),
            "prior_b": self.prior_b.tolist(),
            "data_A": self.data_A.tolist(),
            "data_b": self.data_b.tolist(),
            "arm_steps": self.arm_steps.tolist(),
            "update_counts": self.update_counts.tolist(),
        }

    @classmethod
    def from_state(
        cls, state: dict[str, Any], alpha: float = 0.5, gamma: float | None = None
    ) -> "LinUCB":
        """`gamma` overrides the stored discount (the operator's current
        BANDIT_DISCOUNT); None keeps the stored one."""
        if state.get("format") != STATE_FORMAT:
            raise ValueError("unsupported bandit state format")
        if state.get("actions") != [a.value for a in ACTIONS]:
            raise ValueError("bandit state was saved with a different action set")
        if state.get("n_features") != N_FEATURES:
            raise ValueError("bandit state was saved with a different feature layout")
        bandit = cls(
            n_features=state["n_features"],
            alpha=alpha,
            ridge=state["ridge"],
            gamma=state["gamma"] if gamma is None else gamma,
        )
        arrays = {}
        for name in ("prior_A", "prior_b", "data_A", "data_b"):
            value = np.asarray(state[name], dtype=float)
            if value.shape != getattr(bandit, name).shape:
                raise ValueError("bandit state has the wrong shape")
            if not np.all(np.isfinite(value)):
                raise ValueError("bandit state contains a non-finite value")
            arrays[name] = value
        for name, value in arrays.items():
            setattr(bandit, name, value)
        bandit.arm_steps = np.asarray(state["arm_steps"], dtype=int)
        bandit.update_counts = np.asarray(state["update_counts"], dtype=int)
        return bandit


# Prior strength: PRIOR_CONTEXTS synthetic contexts per arm, each counted
# PRIOR_WEIGHT times - worth ~50 real observations per arm, so a few dozen
# consistent pieces of real feedback visibly move the policy.
PRIOR_CONTEXTS = 200
PRIOR_WEIGHT = 0.25
PRIOR_SEED = 0
# The prior covers every feature direction (counts span their full range),
# so the ridge term only needs to keep A invertible. At ridge 1.0 its
# shrinkage, spread across the correlated probability/logit features,
# moved the warm-start bands to 0.22 / 0.58 / 0.91 instead of reward.py's
# 0.33 / 0.57 / 0.80, and left the count features loose enough that 85 of
# 1,224 attacker-chosen (windows, PII, truncation) combinations got a
# laxer action than the same score with neutral counts. At 0.01: 0.34 /
# 0.58 / 0.81 and none (test_bandit.py pins both).
PRIOR_RIDGE = 0.01


def _saturated(rng: np.random.Generator, near_one: bool) -> float:
    value = float(rng.beta(0.3, 8.0))
    return 1.0 - value if near_one else value


def _prior_inputs(rng: np.random.Generator) -> FeatureInputs:
    # Mirrors the classifier's saturated outputs: most scores sit near 0 or
    # 1, with a uniform band so the middle of the range is covered too.
    kind = rng.random()
    p_attack = float(rng.uniform(0.0, 1.0)) if kind < 0.4 else _saturated(rng, kind >= 0.7)
    injection_share = float(rng.uniform(0.0, 1.0))
    # System prompt: none, an ordinary one (near 0) or one the classifier
    # flags (near 1 - defensive and injected prompts both land there).
    system_kind = rng.random()
    system_attack = None if system_kind < 0.4 else _saturated(rng, system_kind >= 0.7)
    # Counts span the whole range the features encode. A prior that only
    # covered 1-8 windows and 0-3 PII entities left those weights fitted to
    # noise, and an attacker sending 32 windows moved a p=0.6 request from
    # escalate to redact through the extrapolation.
    return FeatureInputs(
        threat_score={
            "benign": 1.0 - p_attack,
            "prompt_injection": p_attack * injection_share,
            "jailbreak": p_attack * (1.0 - injection_share),
        },
        system_prompt_threat_score=(
            None
            if system_attack is None
            else {
                "benign": 1.0 - system_attack,
                "prompt_injection": system_attack,
                "jailbreak": 0.0,
            }
        ),
        scan_windows=int(rng.integers(1, MAX_WINDOWS + 1)),
        scan_truncated=bool(rng.random() < 0.05),
        pii_entity_count=int(rng.integers(0, PII_COUNT_CAP + 1)),
    )


def apply_calibrated_prior(
    bandit: LinUCB,
    n_contexts: int = PRIOR_CONTEXTS,
    weight: float = PRIOR_WEIGHT,
    seed: int = PRIOR_SEED,
) -> LinUCB:
    """Seed every arm with the reward it would earn if the classifier's
    probabilities were calibrated, at the request's effective attack
    probability (conversation and system prompt together - see
    features.effective_attack_probability). Deterministic for a given seed.
    Goes into the prior: never discounted, never counted as feedback."""
    rng = np.random.default_rng(seed)
    for _ in range(n_contexts):
        inputs = _prior_inputs(rng)
        x = build_features(inputs)
        p_eff = effective_attack_probability(inputs)
        for action in ACTIONS:
            bandit.add_prior(x, action, expected_reward(action, p_eff), weight)
    return bandit


def new_bandit(alpha: float = 0.5, gamma: float = 1.0, seed: int | None = None) -> LinUCB:
    """A warm-started bandit - what the gateway runs before any feedback."""
    return apply_calibrated_prior(LinUCB(alpha=alpha, ridge=PRIOR_RIDGE, gamma=gamma, seed=seed))
