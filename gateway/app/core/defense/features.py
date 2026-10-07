"""Context vector construction for the tactical bandit. See
project_plan/06a-adaptive-defense-bandit.md §2.

`build_features` is a pure function of plain numbers, so the gateway stage,
the warm-start prior (bandit.py) and the offline evaluation harness
(training/evaluate_bandit.py) all build vectors the same way - the offline
numbers describe the policy that actually runs.

Every feature is a score, a count or a clock reading, scaled to roughly
[-1, 1]. None is derived from prompt text, so a vector (stored on every
ThreatEvent) can never carry PII.

Feature list (order is the vector layout - bump FEATURE_VERSION on any change):

- bias: constant 1.0
- p_prompt_injection, p_jailbreak: module 5 `threat_score` probabilities
- attack_logit: log-odds of (1 - benign), clipped to +-10, divided by 10
- system_prompt_attack: 1 - benign of `system_prompt_threat_score`
  (0 if the request has no system prompt)
- scan_truncated: module 5 `threat_scan.truncated`, 0 / 1
- scan_windows: `threat_scan.windows` / 32 (the classifier's MAX_WINDOWS)
- pii_entities: total of module 4's `redaction_map` counts, min(n, 10) / 10
- hour_sin, hour_cos: UTC time of day on the unit circle
- team_request_rate: the team's requests so far this minute, min(n, 60) / 60

Why `attack_logit` as well as the raw probabilities: the classifier's
outputs are saturated (most land within 0.01 of 0 or 1), so on the
probability scale 0.98 and 0.9999 look almost identical. The log-odds
separate them, which lets a linear model treat a 0.98 differently from a
0.9999 - the L5-2 false positives ("forget about the budget numbers...")
sit at the low end of that range.
"""
import math
from dataclasses import dataclass

import numpy as np

FEATURE_VERSION = 1

FEATURE_NAMES: tuple[str, ...] = (
    "bias",
    "p_prompt_injection",
    "p_jailbreak",
    "attack_logit",
    "system_prompt_attack",
    "scan_truncated",
    "scan_windows",
    "pii_entities",
    "hour_sin",
    "hour_cos",
    "team_request_rate",
)
N_FEATURES = len(FEATURE_NAMES)

MAX_WINDOWS = 32
PII_COUNT_CAP = 10
TEAM_RATE_CAP = 60
LOGIT_CLIP = 10.0
_EPS = 1e-6


@dataclass(frozen=True)
class FeatureInputs:
    """Everything the bandit observes about one request, as plain values."""

    threat_score: dict[str, float]
    system_prompt_threat_score: dict[str, float] | None = None
    scan_windows: int = 1
    scan_truncated: bool = False
    pii_entity_count: int = 0
    hour_utc: float = 12.0
    team_requests_this_minute: int = 1


def attack_probability(threat_score: dict[str, float]) -> float:
    """Probability that the text is an attack of either kind."""
    return min(1.0, max(0.0, 1.0 - float(threat_score["benign"])))


def _clip01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _check_score(score: dict[str, float]) -> None:
    # Checked before any clamping: Python's min/max silently turn NaN into
    # the other operand (max(0.0, nan) == 0.0), which would make a NaN
    # score read as "certainly benign" - fail-open. Refuse it instead.
    for label in ("benign", "prompt_injection", "jailbreak"):
        if not math.isfinite(float(score[label])):
            raise ValueError("threat score contains a non-finite value")


def build_features(inputs: FeatureInputs) -> np.ndarray:
    score = inputs.threat_score
    _check_score(score)
    if inputs.system_prompt_threat_score:
        _check_score(inputs.system_prompt_threat_score)
    if not math.isfinite(inputs.hour_utc):
        raise ValueError("hour_utc must be finite")
    p_attack = attack_probability(score)
    p = min(1.0 - _EPS, max(_EPS, p_attack))
    logit = math.log(p / (1.0 - p))

    system = inputs.system_prompt_threat_score
    system_attack = attack_probability(system) if system else 0.0

    angle = 2.0 * math.pi * (inputs.hour_utc % 24.0) / 24.0

    vector = np.array(
        [
            1.0,
            _clip01(float(score["prompt_injection"])),
            _clip01(float(score["jailbreak"])),
            max(-LOGIT_CLIP, min(LOGIT_CLIP, logit)) / LOGIT_CLIP,
            system_attack,
            1.0 if inputs.scan_truncated else 0.0,
            min(max(inputs.scan_windows, 0), MAX_WINDOWS) / MAX_WINDOWS,
            min(max(inputs.pii_entity_count, 0), PII_COUNT_CAP) / PII_COUNT_CAP,
            math.sin(angle),
            math.cos(angle),
            min(max(inputs.team_requests_this_minute, 0), TEAM_RATE_CAP) / TEAM_RATE_CAP,
        ],
        dtype=float,
    )
    if not np.all(np.isfinite(vector)):
        # Only reachable through a NaN/inf score - refuse rather than let a
        # poisoned vector into the bandit's matrices.
        raise ValueError("feature vector contains a non-finite value")
    return vector


def features_to_dict(vector: np.ndarray) -> dict[str, float]:
    return {name: float(value) for name, value in zip(FEATURE_NAMES, vector, strict=True)}


def features_from_dict(values: dict[str, float]) -> np.ndarray:
    return np.array([float(values[name]) for name in FEATURE_NAMES], dtype=float)
