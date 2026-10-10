"""State vector for the session agent. See
project_plan/06b-adaptive-defense-rl-session-agent.md §2.

`build_session_features` is a pure function of a `SessionSnapshot`, which
the gateway reads from Redis (app/core/defense/session.py) and the
simulator builds in memory (simulator.py) - one implementation, so the
trained agent sees in production exactly the inputs it was trained on.

Every value is a count, a fraction or a classifier score, so a vector can
never carry prompt text or PII.

Feature list (order is the vector layout - bump SESSION_FEATURE_VERSION on
any change; the DQN weights file records the version it was trained on):

- request_count: requests so far, min(n, 15) / 15
- count_allow, count_redact, count_block, count_escalate: what module 6a
  did to the session's requests (the outcome, i.e. what actually
  happened), each min(c, 10) / 10
- consecutive_refused: trailing run of requests that weren't allowed,
  min(k, 5) / 5
- score_last, score_mean, score_max: module 5 attack probability of the
  latest request, and the mean / max over the last RECENT_WINDOW requests
- score_slope: least-squares slope of those scores per request (the
  plan's "threat score trend"), clipped to [-1, 1]
- share_high: share of those requests scored >= 0.5
- redaction_frequency: share of the session's requests in which module 4
  found PII
- escalation_bias: the session's current bias, in [-0.3, 1]
- challenge_pending: 1 if a `challenge` is waiting for the next request

Left out of the plan's list, on purpose:

- request_rate and session_age (wall-clock time). There is no real
  timing data to train on, so the simulator would have to invent
  benign/attack timing distributions and the agent would learn whatever
  was invented. Both are also attacker-controlled (slow down and they
  look benign). Module 6a dropped its request-rate feature for the same
  reasons (L6a-11). request_count stands in for session age.
- budget_fraction_remaining: budgets are opt-in and per team, not per
  session, so most sessions have no value, and there is no budget data to
  simulate.
"""
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import numpy as np

from app.db.models import DefenseAction

SESSION_FEATURE_VERSION = 1

SESSION_FEATURE_NAMES: tuple[str, ...] = (
    "request_count",
    "count_allow",
    "count_redact",
    "count_block",
    "count_escalate",
    "consecutive_refused",
    "score_last",
    "score_mean",
    "score_max",
    "score_slope",
    "share_high",
    "redaction_frequency",
    "escalation_bias",
    "challenge_pending",
)
N_SESSION_FEATURES = len(SESSION_FEATURE_NAMES)

RECENT_WINDOW = 10
REQUEST_CAP = 15
COUNT_CAP = 10
CONSECUTIVE_CAP = 5
HIGH_SCORE = 0.5


@dataclass(frozen=True)
class SessionSnapshot:
    """Everything the session agent observes, as plain values."""

    request_count: int = 0
    # Module 6a outcome (DefenseAction value) -> number of requests.
    outcome_counts: Mapping[str, int] = field(default_factory=dict)
    consecutive_refused: int = 0
    # Attack probabilities of the most recent requests, oldest first.
    recent_scores: Sequence[float] = ()
    pii_requests: int = 0
    escalation_bias: float = 0.0
    challenge_pending: bool = False

    def count(self, action: DefenseAction) -> int:
        return int(self.outcome_counts.get(action.value, 0))

    @property
    def refused_count(self) -> int:
        return self.request_count - self.count(DefenseAction.ALLOW)


def _capped(value: int, cap: int) -> float:
    return min(max(int(value), 0), cap) / cap


def _slope(scores: Sequence[float]) -> float:
    n = len(scores)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2.0
    y_mean = sum(scores) / n
    num = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(scores))
    den = sum((i - x_mean) ** 2 for i in range(n))
    return max(-1.0, min(1.0, num / den))


def build_session_features(snapshot: SessionSnapshot) -> np.ndarray:
    scores = [float(s) for s in snapshot.recent_scores][-RECENT_WINDOW:]
    if not all(math.isfinite(s) for s in scores):
        # Same reasoning as 6a's features.py: never let NaN read as benign.
        raise ValueError("session scores contain a non-finite value")
    if not math.isfinite(snapshot.escalation_bias):
        raise ValueError("escalation_bias must be finite")
    scores = [min(1.0, max(0.0, s)) for s in scores]
    n = max(snapshot.request_count, 0)

    vector = np.array(
        [
            _capped(n, REQUEST_CAP),
            _capped(snapshot.count(DefenseAction.ALLOW), COUNT_CAP),
            _capped(snapshot.count(DefenseAction.REDACT_AND_ALLOW), COUNT_CAP),
            _capped(snapshot.count(DefenseAction.BLOCK), COUNT_CAP),
            _capped(snapshot.count(DefenseAction.ESCALATE_TO_HUMAN), COUNT_CAP),
            _capped(snapshot.consecutive_refused, CONSECUTIVE_CAP),
            scores[-1] if scores else 0.0,
            float(np.mean(scores)) if scores else 0.0,
            max(scores) if scores else 0.0,
            _slope(scores),
            (sum(s >= HIGH_SCORE for s in scores) / len(scores)) if scores else 0.0,
            min(1.0, snapshot.pii_requests / n) if n else 0.0,
            float(snapshot.escalation_bias),
            1.0 if snapshot.challenge_pending else 0.0,
        ],
        dtype=float,
    )
    return vector


def session_features_to_dict(vector: np.ndarray) -> dict[str, float]:
    return {
        name: float(value) for name, value in zip(SESSION_FEATURE_NAMES, vector, strict=True)
    }
