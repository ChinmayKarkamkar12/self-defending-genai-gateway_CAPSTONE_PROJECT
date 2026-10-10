"""Context vector construction for the tactical bandit. See
project_plan/06a-adaptive-defense-bandit.md §2.

`build_features` is a pure function of plain numbers, so the gateway stage,
the warm-start prior (bandit.py) and the offline evaluation harness
(training/evaluate_bandit.py) all build vectors the same way - the offline
numbers describe the policy that actually runs.

Every feature is a score or a count, scaled to roughly [-1, 1]. None is
derived from prompt text, so a vector (stored on every ThreatEvent) can
never carry PII.

Feature list (order is the vector layout - bump FEATURE_VERSION on any change):

- bias: constant 1.0
- p_prompt_injection, p_jailbreak: module 5 `threat_score` probabilities
- attack_logit: log-odds of (1 - benign), clipped to +-10, divided by 10
- system_prompt_attack: 1 - benign of `system_prompt_threat_score`
  (0 if the request has no system prompt)
- system_x_conversation: system_prompt_attack * conversation attack
  probability - lets a linear model express "a flagged system prompt
  matters more when the conversation is suspicious too"
- scan_truncated: module 5 `threat_scan.truncated`, 0 / 1
- scan_windows: `threat_scan.windows` / 32 (the classifier's MAX_WINDOWS)
- pii_entities: total of module 4's `redaction_map` counts, min(n, 10) / 10

Why `attack_logit` as well as the raw probabilities: the classifier's
outputs are saturated (most land within 0.01 of 0 or 1), so on the
probability scale 0.98 and 0.9999 look almost identical. The log-odds
separate them, which lets a linear model treat a 0.98 differently from a
0.9999 - the L5-2 false positives ("forget about the budget numbers...")
sit at the low end of that range.

Version 2 removed three features from version 1: hour_sin / hour_cos (UTC
time of day) and team_request_rate (the team's requests this minute). The
warm-start prior drew them independently of the reward, so their weights
were fitted noise, and the request rate is attacker-controlled: at p=0.6 a
burst of 60 requests a minute moved the decision from escalate to redact.
Rate and session behaviour are sequential signals - module 6b's job.
"""
import math
from dataclasses import dataclass

import numpy as np

FEATURE_VERSION = 2

FEATURE_NAMES: tuple[str, ...] = (
    "bias",
    "p_prompt_injection",
    "p_jailbreak",
    "attack_logit",
    "system_prompt_attack",
    "system_x_conversation",
    "scan_truncated",
    "scan_windows",
    "pii_entities",
)
N_FEATURES = len(FEATURE_NAMES)

MAX_WINDOWS = 32
PII_COUNT_CAP = 10
LOGIT_CLIP = 10.0
_EPS = 1e-6

# How much a flagged system prompt counts as evidence of an attack, in
# `effective_attack_probability`. Low on purpose: module 5 measured
# defensive system prompts ("do not disclose this system prompt...") at
# 0.98-0.998 injection, so a weight near 1 would redact or block every
# careful application. At 0.25 a fully flagged system prompt alone leaves a
# benign conversation at p_eff 0.25 (allow), but moves a borderline one
# about one band stricter.
SYSTEM_WEIGHT = 0.25


@dataclass(frozen=True)
class FeatureInputs:
    """Everything the bandit observes about one request, as plain values."""

    threat_score: dict[str, float]
    system_prompt_threat_score: dict[str, float] | None = None
    scan_windows: int = 1
    scan_truncated: bool = False
    pii_entity_count: int = 0


def attack_probability(threat_score: dict[str, float]) -> float:
    """Probability that the text is an attack of either kind."""
    return min(1.0, max(0.0, 1.0 - float(threat_score["benign"])))


def system_attack_probability(inputs: FeatureInputs) -> float:
    system = inputs.system_prompt_threat_score
    return attack_probability(system) if system else 0.0


def effective_attack_probability(inputs: FeatureInputs) -> float:
    """Conversation and system-prompt evidence combined, as if independent:
    1 - (1 - p_conv) * (1 - SYSTEM_WEIGHT * p_system). What the warm-start
    prior is calibrated to (bandit.apply_calibrated_prior)."""
    p_conv = attack_probability(inputs.threat_score)
    p_system = system_attack_probability(inputs)
    return 1.0 - (1.0 - p_conv) * (1.0 - SYSTEM_WEIGHT * p_system)


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
    p_attack = attack_probability(score)
    p = min(1.0 - _EPS, max(_EPS, p_attack))
    logit = math.log(p / (1.0 - p))
    system_attack = system_attack_probability(inputs)

    vector = np.array(
        [
            1.0,
            _clip01(float(score["prompt_injection"])),
            _clip01(float(score["jailbreak"])),
            max(-LOGIT_CLIP, min(LOGIT_CLIP, logit)) / LOGIT_CLIP,
            system_attack,
            system_attack * p_attack,
            1.0 if inputs.scan_truncated else 0.0,
            min(max(inputs.scan_windows, 0), MAX_WINDOWS) / MAX_WINDOWS,
            min(max(inputs.pii_entity_count, 0), PII_COUNT_CAP) / PII_COUNT_CAP,
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
