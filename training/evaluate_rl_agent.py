"""Three-way evaluation of the session agent (module 6b): trained DQN vs.
maintain-only baseline vs. rule-based fallback. See
project_plan/06b-adaptive-defense-rl-session-agent.md §6, §7 task 7-8.

Run after train_rl_agent.py, from the repo root:
    gateway/.venv/Scripts/python.exe training/evaluate_rl_agent.py [--ship]

**Held-out data.** Sessions are built from the **test** split's prompts
(the agents trained on val), under each preset in
generate_sessions.HELDOUT: the training generator ("standard", 20% attack
sessions), a 50% and a 5% attack-session rate, and a shifted world (longer
sessions, more false-positive-prone users, an attacker who learns from
refusals).

**Paired comparison.** Session i of a preset uses seed i for every policy
(common random numbers): the same session type, length, users and
attacker draws, until the policies' choices make the sessions diverge.
Differences are reported per session with a 95% confidence interval.

**Metrics** (the plan's three, plus what they hide):
  return            mean episode reward (rl/reward.py; shaping excluded)
  breach rate       attack sessions in which an attack request was allowed
  attack flagged    attack sessions the policy intervened in
  benign friction   share of benign requests refused (6a's refusals plus
                    every request a lockout refused)
  benign flagged    benign sessions the policy intervened in
  benign lockout    benign sessions locked out - the costliest mistake,
                    since a session is a whole API key (L6b-1)

**Go/no-go (decided before seeing results, recorded in PROGRESS.md):**
a DQN variant (with or without shaping) is GO if, in at least 4 of its 5
training seeds, on every held-out preset,
  1. its paired return difference against BOTH baselines has a 95% CI
     entirely above 0, and
  2. its benign lockout rate is no more than the rule's + 1 point.
Otherwise the rule-based fallback stays the default (SESSION_POLICY=rule).

If a variant is GO, --ship copies one of its seeds' weights to
gateway/app/core/defense/rl/dqn_policy.npz. The seed is chosen on
*validation* sessions (val prompts, seeds never used in training), not on
the test results.

Result of the 2026-10-10 run: NO-GO (training/README.md). The shipped
dqn_policy.npz was copied by hand: shaping seed 0, chosen on validation
sessions from the two seeds that met the criterion individually. It is an
opt-in (SESSION_POLICY=dqn), not the default.
"""

import argparse
import json
import math
import shutil
from dataclasses import replace
from pathlib import Path

import generate_sessions as gs
import numpy as np

from app.core.defense.rl.dqn import DEFAULT_WEIGHTS_PATH, DQNPolicy
from app.core.defense.rl.fallback_policy import MaintainPolicy, RuleBasedPolicy
from app.core.defense.rl.simulator import EpisodeStats, run_episode

AGENT_DIR = gs.REPO_ROOT / "training" / "checkpoints" / "rl_agent"
OUTPUT_PATH = gs.REPO_ROOT / "training" / "checkpoints" / "rl_eval.json"
N_SESSIONS = 3000
N_VALIDATION = 2000
VALIDATION_SEED_OFFSET = 10_000_000  # far from anything training drew
SEEDS_REQUIRED = 4
LOCKOUT_SLACK = 0.01


def metrics(stats: list[EpisodeStats]) -> dict[str, float]:
    attacks = [s for s in stats if s.label.value == "attack"]
    benign = [s for s in stats if s.label.value == "benign"]

    def share(items, pred):
        return sum(pred(s) for s in items) / len(items) if items else float("nan")

    return {
        "return": float(np.mean([s.env_return for s in stats])),
        "breach_rate": share(attacks, lambda s: s.breached),
        "attack_flagged": share(attacks, lambda s: s.intervened),
        "attack_locked_out": share(attacks, lambda s: s.locked_out),
        "benign_friction": sum(s.benign_refused for s in benign)
        / max(sum(s.benign_requests for s in benign), 1),
        "benign_flagged": share(benign, lambda s: s.intervened),
        "benign_lockout": share(benign, lambda s: s.locked_out),
    }


def paired(a: list[EpisodeStats], b: list[EpisodeStats]) -> dict[str, float]:
    diff = np.array([x.env_return - y.env_return for x, y in zip(a, b, strict=True)])
    half = 1.96 * diff.std(ddof=1) / math.sqrt(len(diff))
    return {"mean": float(diff.mean()), "ci_low": float(diff.mean() - half),
            "ci_high": float(diff.mean() + half)}


def play(split: str, config, policy, n: int, offset: int = 0) -> list[EpisodeStats]:
    sim = gs.simulator(split, config)
    return [run_episode(sim, policy.decide, offset + i) for i in range(n)]


def agent_files() -> dict[str, list[Path]]:
    variants: dict[str, list[Path]] = {}
    for variant in ("noshaping", "shaping"):
        files = sorted(AGENT_DIR.glob(f"dqn_{variant}_seed[0-9].npz"))
        if files:
            variants[variant] = files
    if not variants:
        raise SystemExit(f"no trained agents in {AGENT_DIR} - run train_rl_agent.py first")
    return variants


def learning_curve(npz: Path) -> dict[str, float]:
    log = json.loads(npz.with_suffix(".json").read_text())
    returns = log["episode_returns"]
    k = max(len(returns) // 10, 1)
    return {"first_10pct": float(np.mean(returns[:k])), "last_10pct": float(np.mean(returns[-k:])),
            "episodes": len(returns)}


def table(rows: dict[str, dict[str, float]]) -> str:
    cols = ["return", "breach_rate", "attack_flagged", "benign_friction", "benign_flagged",
            "benign_lockout"]
    lines = ["| policy | " + " | ".join(cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for name, m in rows.items():
        lines.append(f"| {name} | " + " | ".join(f"{m[c]:.3f}" for c in cols) + " |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ship", action="store_true", help="copy the chosen GO agent")
    parser.add_argument("--sessions", type=int, default=N_SESSIONS)
    args = parser.parse_args()

    variants = agent_files()
    baselines = {"maintain": MaintainPolicy(), "rule": RuleBasedPolicy()}
    results: dict = {"presets": {}, "learning_curves": {}, "go_no_go": {}}

    for files in variants.values():
        for f in files:
            results["learning_curves"][f.stem] = learning_curve(f)

    passes: dict[str, int] = {v: 0 for v in variants}
    per_seed_ok: dict[str, dict[str, bool]] = {v: {f.stem: True for f in fs}
                                               for v, fs in variants.items()}
    for preset, config in gs.HELDOUT.items():
        config = replace(config, shaping_coef=0.0)
        played = {name: play(gs.EVAL_SPLIT, config, p, args.sessions)
                  for name, p in baselines.items()}
        rows = {name: metrics(s) for name, s in played.items()}
        comparisons = {}
        for variant, files in variants.items():
            seed_rows = []
            for f in files:
                stats = play(gs.EVAL_SPLIT, config, DQNPolicy.load(f), args.sessions)
                m = metrics(stats)
                vs_maintain = paired(stats, played["maintain"])
                vs_rule = paired(stats, played["rule"])
                ok = (
                    vs_maintain["ci_low"] > 0
                    and vs_rule["ci_low"] > 0
                    and m["benign_lockout"] <= rows["rule"]["benign_lockout"] + LOCKOUT_SLACK
                )
                per_seed_ok[variant][f.stem] &= ok
                comparisons[f.stem] = {"metrics": m, "vs_maintain": vs_maintain,
                                       "vs_rule": vs_rule, "criterion_met": ok}
                seed_rows.append(m)
            rows[f"dqn_{variant} (mean of {len(files)} seeds)"] = {
                k: float(np.mean([r[k] for r in seed_rows])) for k in seed_rows[0]
            }
        results["presets"][preset] = {"baselines": {k: rows[k] for k in baselines},
                                      "dqn": comparisons, "table": rows}
        print(f"\n### {preset} ({args.sessions} sessions, test prompts)\n")
        print(table(rows))
        print()
        for stem, c in comparisons.items():
            print(f"- {stem}: vs maintain {c['vs_maintain']['mean']:+.3f} "
                  f"[{c['vs_maintain']['ci_low']:+.3f}, {c['vs_maintain']['ci_high']:+.3f}], "
                  f"vs rule {c['vs_rule']['mean']:+.3f} "
                  f"[{c['vs_rule']['ci_low']:+.3f}, {c['vs_rule']['ci_high']:+.3f}]"
                  f"{'' if c['criterion_met'] else '  (criterion not met)'}")

    go_variants = []
    for variant in variants:
        passes[variant] = sum(per_seed_ok[variant].values())
        go = passes[variant] >= SEEDS_REQUIRED
        results["go_no_go"][variant] = {"seeds_passing": passes[variant],
                                        "seeds": len(variants[variant]), "go": go}
        if go:
            go_variants.append(variant)
    decision = "GO" if go_variants else "NO-GO"
    results["decision"] = decision
    print(f"\n## Go/no-go: {decision}")
    for variant, r in results["go_no_go"].items():
        print(f"- dqn_{variant}: {r['seeds_passing']}/{r['seeds']} seeds meet the criterion "
              f"on every preset (need {SEEDS_REQUIRED})")

    if go_variants:
        # Pick a seed on validation sessions (val prompts, unseen seeds).
        candidates = [f for v in go_variants for f in variants[v] if per_seed_ok[v][f.stem]]
        val_config = replace(gs.TRAIN, shaping_coef=0.0)
        scores = {
            f.stem: metrics(play(gs.TRAIN_SPLIT, val_config, DQNPolicy.load(f), N_VALIDATION,
                                 VALIDATION_SEED_OFFSET))["return"]
            for f in candidates
        }
        chosen = max(scores, key=scores.get)
        results["chosen"] = {"agent": chosen, "validation_returns": scores}
        print(f"- chosen on validation sessions: {chosen} ({scores[chosen]:.3f})")
        if args.ship:
            shutil.copyfile(AGENT_DIR / f"{chosen}.npz", DEFAULT_WEIGHTS_PATH)
            print(f"- shipped to {DEFAULT_WEIGHTS_PATH.relative_to(gs.REPO_ROOT)}")

    print("\n## Learning curves (mean episode return, first vs last 10% of training)")
    for stem, c in results["learning_curves"].items():
        print(f"- {stem}: {c['first_10pct']:+.3f} -> {c['last_10pct']:+.3f} "
              f"({c['episodes']} episodes)")
    OUTPUT_PATH.write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
