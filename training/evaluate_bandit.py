"""Offline evaluation of module 6a's tactical bandit against static-threshold
baselines. See project_plan/06a-adaptive-defense-bandit.md §7 task 8, §8.

Run from the repo root with the project venv, after train_classifier.py:
    gateway/.venv/Scripts/python.exe training/evaluate_bandit.py

Everything the gateway decides with is imported from the gateway itself -
the classifier's windowed scoring, the feature builder, the LinUCB bandit
with its warm-start prior, the safety mask and the reward table - so these
numbers describe the policy that actually runs, not a reimplementation.

Data: module 5's held-out splits (val 196 rows, test 194 rows), never seen
in classifier training. Each row is scored once with the production
classifier and cached to training/data/bandit_scores_<split>.jsonl.

Policies compared, all scored with the same reward table (reward.py):

  static@0.5      block if attack probability >= 0.5, else allow
  static-tuned    the same, with the threshold tuned on the *other* split
                  (the fairest static baseline we can build without
                  peeking at the evaluation data)
  prior-frozen    the bandit's warm-start policy with learning switched off
                  (isolates what learning adds on top of the prior)
  bandit          the full LinUCB policy, learning online from feedback

Feedback regimes for the bandit:

  full            every decision is labelled right away - the standard
                  bandit-evaluation setting, an upper bound
  realistic       what production gives: every escalation is reviewed, plus
                  a BANDIT_SPOT_CHECK_RATE sample of the other decisions

Experiment A (main result, i.i.d.): 2-fold - tune on val, run on test, and
vice versa. One pass over the evaluation split per run, no repeats, so the
bandit can't memorise individual rows; 30 shuffled orders per fold.

Experiment B (base-rate shift): both splits are ~50% attacks, real traffic
is mostly benign. Streams of 1,000 requests drawn from the evaluation split
at 10% and 2% attack rates (with replacement - see the caveat in
training/README.md), 20 seeds each. Adds a hindsight-optimal static
threshold (tuned on the stream itself; not achievable in practice) as a
reference ceiling for static policies.

Experiment C (controlled false-positive drift - a simulation, labelled as
such): one team's benign traffic trips the classifier, the L5-2 problem.
20% of benign requests get an injection score drawn uniformly from
[0.95, 0.995] - the band where the real false positives we measured sit
("Forget about the budget numbers..." 0.98; three Alpaca instructions at
0.990-0.995, see --external). Real attacks also occur in that band (11 of
190 held-out attacks score 0.95-0.999), so it's a genuine trade-off, not a
free win. Everything else is real held-out data at a 10% attack rate.

`--external` additionally re-runs the two real-data probes behind the
README's "the classifier is bimodal" finding (downloads
Lakera/gandalf_ignore_instructions and tatsu-lab/alpaca).

Writes training/checkpoints/bandit_eval.json and prints markdown tables
for training/README.md.
"""

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "gateway"))
# app.config needs these to import; the evaluation touches no database,
# Redis or provider, so placeholder values are enough.
for _name, _value in {
    "POSTGRES_DSN": "postgresql://unused:unused@localhost:5432/unused",
    "REDIS_URL": "redis://localhost:6379/0",
    "OPENAI_API_KEY": "unused",
    "ANTHROPIC_API_KEY": "unused",
    "REDACTION_VAULT_KEY": "CsmRGHfMdzTqw8f6YCOh6vsLs9cAxgnDuoEDsPMOrw0=",
}.items():
    os.environ.setdefault(_name, _value)

from app.config import settings  # noqa: E402
from app.core.defense.bandit import new_bandit, safety_mask  # noqa: E402
from app.core.defense.features import (  # noqa: E402
    FeatureInputs,
    attack_probability,
    build_features,
)
from app.core.defense.reward import proxy_reward  # noqa: E402
from app.core.threat.classifier import ThreatClassifier  # noqa: E402 - torch loads lazily
from app.db.models import DefenseAction, ThreatLabel  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("evaluate_bandit")

DATA_DIR = REPO_ROOT / "training" / "data"
OUTPUT_PATH = REPO_ROOT / "training" / "checkpoints" / "bandit_eval.json"
SPLITS = ("val", "test")
A_SHUFFLES = 30
B_STREAM = 1000
B_SEEDS = 20
B_ATTACK_RATES = (0.10, 0.02)
C_ATTACK_RATE = 0.10
C_HARD_NEGATIVE_SHARE = 0.20
C_BAND = (0.95, 0.995)
C_SPOT_CHECK_SWEEP = (0.02, 0.05, 0.10, 0.25)
THRESHOLD_GRID = np.round(np.arange(0.01, 1.0, 0.01), 2)

A = DefenseAction


@dataclass(frozen=True)
class Row:
    threat_score: dict[str, float]
    windows: int
    truncated: bool
    is_attack: bool

    @property
    def p_attack(self) -> float:
        return attack_probability(self.threat_score)

    @property
    def label(self) -> ThreatLabel:
        return ThreatLabel.ATTACK if self.is_attack else ThreatLabel.BENIGN


# ---------------------------------------------------------------- scoring


def load_scored(split: str) -> list[Row]:
    cache = DATA_DIR / f"bandit_scores_{split}.jsonl"
    if not cache.exists():
        logger.info("scoring %s split with the production classifier (cached afterwards)", split)
        classifier = ThreatClassifier()
        source = DATA_DIR / f"{split}.jsonl"
        lines = []
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            result = classifier.score_texts([row["text"]])
            lines.append(
                json.dumps(
                    {
                        "threat_score": result.score.as_dict(),
                        "windows": result.windows,
                        "truncated": result.truncated,
                        # label 0 = benign, 1 = prompt_injection, 2 = jailbreak
                        "is_attack": row["label"] != 0,
                    }
                )
            )
        cache.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [
        Row(**json.loads(line))
        for line in cache.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# --------------------------------------------------------------- policies


@dataclass
class Tally:
    rewards: list[float] = field(default_factory=list)
    counts: dict[str, int] = field(
        default_factory=lambda: {
            "attacks": 0,
            "benign": 0,
            "attack_allowed": 0,
            "attack_redacted": 0,
            "benign_refused": 0,
            "benign_redacted": 0,
            "escalations": 0,
            "labels_used": 0,
        }
    )

    def record(self, row: Row, action: DefenseAction) -> float:
        reward = proxy_reward(action, row.label)
        self.rewards.append(reward)
        c = self.counts
        c["attacks" if row.is_attack else "benign"] += 1
        if action == A.ESCALATE_TO_HUMAN:
            c["escalations"] += 1
        if row.is_attack and action == A.ALLOW:
            c["attack_allowed"] += 1
        if row.is_attack and action == A.REDACT_AND_ALLOW:
            c["attack_redacted"] += 1
        if not row.is_attack and action in (A.BLOCK, A.ESCALATE_TO_HUMAN):
            c["benign_refused"] += 1
        if not row.is_attack and action == A.REDACT_AND_ALLOW:
            c["benign_redacted"] += 1
        return reward

    def summary(self) -> dict[str, float]:
        c = self.counts
        n = len(self.rewards)
        return {
            "mean_reward": float(np.mean(self.rewards)),
            "attack_allowed_rate": c["attack_allowed"] / max(c["attacks"], 1),
            "attack_redacted_rate": c["attack_redacted"] / max(c["attacks"], 1),
            "benign_refused_rate": c["benign_refused"] / max(c["benign"], 1),
            "benign_redacted_rate": c["benign_redacted"] / max(c["benign"], 1),
            "escalations_per_1000": 1000 * c["escalations"] / n,
            "labels_used": c["labels_used"],
        }


def static_action(row: Row, threshold: float) -> DefenseAction:
    return A.BLOCK if row.p_attack >= threshold else A.ALLOW


def tune_threshold(rows: list[Row]) -> float:
    def mean_reward(threshold: float) -> float:
        return float(np.mean([proxy_reward(static_action(r, threshold), r.label) for r in rows]))

    return float(max(THRESHOLD_GRID, key=mean_reward))


def run_static(stream: list[Row], threshold: float) -> dict[str, float]:
    tally = Tally()
    for row in stream:
        tally.record(row, static_action(row, threshold))
    return tally.summary()


def run_bandit(
    stream: list[Row],
    seed: int,
    learn: bool,
    regime: str,
    spot_check_rate: float | None = None,
) -> tuple[dict[str, float], list[float]]:
    """One online run. Context features the offline data doesn't have
    (time of day, team request rate) are drawn at random, as they'd vary
    in production; PII counts are 0 (the benchmarks contain none)."""
    rng = np.random.default_rng(seed)
    if spot_check_rate is None:
        spot_check_rate = settings.BANDIT_SPOT_CHECK_RATE
    bandit = new_bandit(alpha=settings.BANDIT_ALPHA, seed=seed)
    tally = Tally()
    for row in stream:
        x = build_features(
            FeatureInputs(
                threat_score=row.threat_score,
                scan_windows=row.windows,
                scan_truncated=row.truncated,
                pii_entity_count=0,
                hour_utc=float(rng.uniform(0, 24)),
                team_requests_this_minute=int(rng.integers(1, 31)),
            )
        )
        masked = safety_mask(row.p_attack, settings.BANDIT_ALLOW_MASK_THRESHOLD)
        action = bandit.select(x, masked=masked).action
        reward = tally.record(row, action)
        if not learn:
            continue
        labelled = (
            regime == "full"
            or action == A.ESCALATE_TO_HUMAN
            or rng.random() < spot_check_rate
        )
        if labelled:
            bandit.update(x, action, reward)
            tally.counts["labels_used"] += 1
    return tally.summary(), tally.rewards


# ------------------------------------------------------------ aggregation


def aggregate(runs: list[dict[str, float]]) -> dict[str, dict[str, float]]:
    return {
        key: {
            "mean": float(np.mean([r[key] for r in runs])),
            "std": float(np.std([r[key] for r in runs])),
        }
        for key in runs[0]
    }


def learning_curve(reward_lists: list[list[float]], n_bins: int = 4) -> list[float]:
    """Mean reward per consecutive quarter of the stream, averaged over runs."""
    per_run = [[float(np.mean(chunk)) for chunk in np.array_split(r, n_bins)] for r in reward_lists]
    return [float(v) for v in np.mean(per_run, axis=0)]


def paired_difference(a: list[float], b: list[float]) -> dict[str, float]:
    diff = np.asarray(a) - np.asarray(b)
    return {
        "mean": float(diff.mean()),
        "std": float(diff.std()),
        "runs_bandit_better": int((diff > 0).sum()),
        "runs": len(diff),
    }


# ------------------------------------------------------------ experiments


def experiment_a(data: dict[str, list[Row]]) -> dict:
    results: dict = {}
    pooled: dict[str, list[dict[str, float]]] = {}
    pooled_rewards: dict[str, list[list[float]]] = {}
    for eval_split, tune_split in (("test", "val"), ("val", "test")):
        rows = data[eval_split]
        tuned = tune_threshold(data[tune_split])
        results[f"tuned_threshold_on_{tune_split}"] = tuned
        for i in range(A_SHUFFLES):
            seed = 1000 * (eval_split == "val") + i
            order = np.random.default_rng(seed).permutation(len(rows))
            stream = [rows[j] for j in order]
            pooled.setdefault("static@0.5", []).append(run_static(stream, 0.5))
            pooled.setdefault("static-tuned", []).append(run_static(stream, tuned))
            summary, _ = run_bandit(stream, seed, learn=False, regime="full")
            pooled.setdefault("prior-frozen", []).append(summary)
            for regime in ("full", "realistic"):
                summary, rewards = run_bandit(stream, seed, learn=True, regime=regime)
                pooled.setdefault(f"bandit ({regime})", []).append(summary)
                pooled_rewards.setdefault(regime, []).append(rewards)

    results["policies"] = {name: aggregate(runs) for name, runs in pooled.items()}
    results["bandit_minus_static_tuned"] = {
        regime: paired_difference(
            [r["mean_reward"] for r in pooled[f"bandit ({regime})"]],
            [r["mean_reward"] for r in pooled["static-tuned"]],
        )
        for regime in ("full", "realistic")
    }
    results["learning_curve_quarters"] = {
        regime: learning_curve(rewards) for regime, rewards in pooled_rewards.items()
    }
    return results


def sample_stream(rows: list[Row], attack_rate: float, n: int, seed: int) -> list[Row]:
    rng = np.random.default_rng(seed)
    attacks = [r for r in rows if r.is_attack]
    benign = [r for r in rows if not r.is_attack]
    return [
        attacks[rng.integers(len(attacks))]
        if rng.random() < attack_rate
        else benign[rng.integers(len(benign))]
        for _ in range(n)
    ]


def experiment_b(data: dict[str, list[Row]]) -> dict:
    results: dict = {}
    for rate in B_ATTACK_RATES:
        pooled: dict[str, list[dict[str, float]]] = {}
        rewards: dict[str, list[list[float]]] = {}
        for eval_split, tune_split in (("test", "val"), ("val", "test")):
            tuned = tune_threshold(data[tune_split])
            for i in range(B_SEEDS // 2):
                seed = 50_000 + int(rate * 1000) * 100 + 1000 * (eval_split == "val") + i
                stream = sample_stream(data[eval_split], rate, B_STREAM, seed)
                pooled.setdefault("static-tuned", []).append(run_static(stream, tuned))
                hindsight = tune_threshold(stream)
                pooled.setdefault("static-hindsight (ceiling)", []).append(
                    run_static(stream, hindsight)
                )
                summary, _ = run_bandit(stream, seed, learn=False, regime="full")
                pooled.setdefault("prior-frozen", []).append(summary)
                for regime in ("full", "realistic"):
                    summary, r = run_bandit(stream, seed, learn=True, regime=regime)
                    pooled.setdefault(f"bandit ({regime})", []).append(summary)
                    rewards.setdefault(regime, []).append(r)
        results[f"attack_rate_{rate}"] = {
            "policies": {name: aggregate(runs) for name, runs in pooled.items()},
            "bandit_minus_static_tuned": {
                regime: paired_difference(
                    [r["mean_reward"] for r in pooled[f"bandit ({regime})"]],
                    [r["mean_reward"] for r in pooled["static-tuned"]],
                )
                for regime in ("full", "realistic")
            },
            "learning_curve_quarters": {
                regime: learning_curve(r) for regime, r in rewards.items()
            },
        }
    return results


def drifted_stream(rows: list[Row], n: int, seed: int) -> list[Row]:
    rng = np.random.default_rng(seed)
    stream = []
    for row in sample_stream(rows, C_ATTACK_RATE, n, seed):
        if not row.is_attack and rng.random() < C_HARD_NEGATIVE_SHARE:
            p = float(rng.uniform(*C_BAND))
            row = Row(
                threat_score={"benign": 1.0 - p, "prompt_injection": p, "jailbreak": 0.0},
                windows=row.windows,
                truncated=row.truncated,
                is_attack=False,
            )
        stream.append(row)
    return stream


def experiment_c(data: dict[str, list[Row]]) -> dict:
    pooled: dict[str, list[dict[str, float]]] = {}
    rewards: dict[str, list[list[float]]] = {}
    sweep: dict[float, list[dict[str, float]]] = {}
    for eval_split, tune_split in (("test", "val"), ("val", "test")):
        tuned = tune_threshold(data[tune_split])
        for i in range(B_SEEDS // 2):
            seed = 90_000 + 1000 * (eval_split == "val") + i
            stream = drifted_stream(data[eval_split], B_STREAM, seed)
            pooled.setdefault("static-tuned", []).append(run_static(stream, tuned))
            pooled.setdefault("static-hindsight (ceiling)", []).append(
                run_static(stream, tune_threshold(stream))
            )
            summary, _ = run_bandit(stream, seed, learn=False, regime="full")
            pooled.setdefault("prior-frozen", []).append(summary)
            for regime in ("full", "realistic"):
                summary, r = run_bandit(stream, seed, learn=True, regime=regime)
                pooled.setdefault(f"bandit ({regime})", []).append(summary)
                rewards.setdefault(regime, []).append(r)
            for rate in C_SPOT_CHECK_SWEEP:
                summary, _ = run_bandit(
                    stream, seed, learn=True, regime="realistic", spot_check_rate=rate
                )
                sweep.setdefault(rate, []).append(summary)
    return {
        "spot_check_sweep": {
            str(rate): {
                "mean_reward": aggregate(runs)["mean_reward"],
                "labels_per_1000": aggregate(runs)["labels_used"]["mean"] * 1000 / B_STREAM,
                "benign_refused_rate": aggregate(runs)["benign_refused_rate"]["mean"],
            }
            for rate, runs in sweep.items()
        },
        "policies": {name: aggregate(runs) for name, runs in pooled.items()},
        "bandit_minus_static_tuned": {
            regime: paired_difference(
                [r["mean_reward"] for r in pooled[f"bandit ({regime})"]],
                [r["mean_reward"] for r in pooled["static-tuned"]],
            )
            for regime in ("full", "realistic")
        },
        "bandit_minus_prior_frozen": {
            regime: paired_difference(
                [r["mean_reward"] for r in pooled[f"bandit ({regime})"]],
                [r["mean_reward"] for r in pooled["prior-frozen"]],
            )
            for regime in ("full", "realistic")
        },
        "learning_curve_quarters": {regime: learning_curve(r) for regime, r in rewards.items()},
    }


def score_bands(probs: list[float]) -> dict[str, int]:
    edges = [(0.0, 0.01), (0.01, 0.5), (0.5, 0.95), (0.95, 0.999), (0.999, 1.01)]
    return {f"{lo}-{min(hi, 1.0)}": sum(lo <= p < hi for p in probs) for lo, hi in edges}


def external_probes() -> dict:
    """Score two public datasets the classifier never trained on: real
    injection attempts from Lakera's Gandalf game, and real benign Alpaca
    instructions that use injection-like words."""
    from datasets import load_dataset  # training-only dependency

    classifier = ThreatClassifier()

    def p_attack(text: str) -> float:
        return 1.0 - classifier.score_texts([text]).score.benign

    gandalf = [r["text"] for r in load_dataset("Lakera/gandalf_ignore_instructions")["test"]]

    seen = set()
    for split in ("train", "val", "test"):
        for line in (DATA_DIR / f"{split}.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                seen.add(json.loads(line)["text"].strip())
    pattern = re.compile(
        r"\b(ignore|forget|disregard|pretend|act as|instead|override|bypass|reveal"
        r"|you are now|from now on|roleplay|role-play)\b",
        re.IGNORECASE,
    )
    alpaca = [
        r["instruction"] + ("\n" + r["input"] if r["input"] else "")
        for r in load_dataset("tatsu-lab/alpaca")["train"]
        if pattern.search(r["instruction"]) and r["instruction"].strip() not in seen
    ]
    return {
        "gandalf_attacks_test_split": score_bands([p_attack(t) for t in gandalf]),
        "alpaca_benign_injection_vocabulary": score_bands([p_attack(t) for t in alpaca]),
    }


# ---------------------------------------------------------------- output


def markdown_table(policies: dict[str, dict[str, dict[str, float]]]) -> str:
    header = (
        "| Policy | Mean reward / request | Attacks allowed | Attacks redacted "
        "| Benign refused | Benign redacted | Escalations / 1k |\n"
        "|---|---|---|---|---|---|---|"
    )
    lines = [header]
    for name, m in policies.items():
        lines.append(
            f"| {name} | {m['mean_reward']['mean']:.3f} ± {m['mean_reward']['std']:.3f} "
            f"| {100 * m['attack_allowed_rate']['mean']:.1f}% "
            f"| {100 * m['attack_redacted_rate']['mean']:.1f}% "
            f"| {100 * m['benign_refused_rate']['mean']:.1f}% "
            f"| {100 * m['benign_redacted_rate']['mean']:.1f}% "
            f"| {m['escalations_per_1000']['mean']:.0f} |"
        )
    return "\n".join(lines)


def main() -> None:
    data = {split: load_scored(split) for split in SPLITS}
    for split, rows in data.items():
        logger.info(
            "%s: %d rows, %d attacks", split, len(rows), sum(r.is_attack for r in rows)
        )

    results = {
        "settings": {
            "bandit_alpha": settings.BANDIT_ALPHA,
            "allow_mask_threshold": settings.BANDIT_ALLOW_MASK_THRESHOLD,
            "spot_check_rate": settings.BANDIT_SPOT_CHECK_RATE,
        },
        "experiment_a_iid": experiment_a(data),
        "experiment_b_base_rate_shift": experiment_b(data),
        "experiment_c_false_positive_drift": experiment_c(data),
    }
    if "--external" in sys.argv:
        results["external_probes"] = external_probes()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")

    a = results["experiment_a_iid"]
    print("\n## Experiment A - i.i.d. held-out data (2 folds x 30 orders)\n")
    print(
        f"Tuned static thresholds: {a['tuned_threshold_on_val']} (on val), "
        f"{a['tuned_threshold_on_test']} (on test)\n"
    )
    print(markdown_table(a["policies"]))
    print("\nBandit minus static-tuned, paired per run:", a["bandit_minus_static_tuned"])
    print("Learning curve (mean reward per quarter of stream):", a["learning_curve_quarters"])
    for key, block in results["experiment_b_base_rate_shift"].items():
        print(f"\n## Experiment B - {key} ({B_SEEDS} streams x {B_STREAM} requests)\n")
        print(markdown_table(block["policies"]))
        print("\nBandit minus static-tuned, paired per run:", block["bandit_minus_static_tuned"])
        print("Learning curve:", block["learning_curve_quarters"])
    c = results["experiment_c_false_positive_drift"]
    print(f"\n## Experiment C - false-positive drift ({B_SEEDS} streams x {B_STREAM} requests)\n")
    print(markdown_table(c["policies"]))
    print("\nBandit minus static-tuned, paired per run:", c["bandit_minus_static_tuned"])
    print("Bandit minus prior-frozen, paired per run:", c["bandit_minus_prior_frozen"])
    print("Learning curve:", c["learning_curve_quarters"])
    print("\n| Spot-check rate | Labels / 1k requests | Mean reward | Benign refused |")
    print("|---|---|---|---|")
    for rate, m in c["spot_check_sweep"].items():
        print(
            f"| {float(rate):.0%} | {m['labels_per_1000']:.0f} "
            f"| {m['mean_reward']['mean']:.3f} ± {m['mean_reward']['std']:.3f} "
            f"| {100 * m['benign_refused_rate']:.1f}% |"
        )
    if "external_probes" in results:
        print("\n## External probes (attack-probability bands)\n")
        print(json.dumps(results["external_probes"], indent=2))
    logger.info("\nwrote %s", OUTPUT_PATH)


if __name__ == "__main__":
    main()
