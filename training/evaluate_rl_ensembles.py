"""Go/no-go evaluation of the third session-agent run: 3 voting ensembles of 5
DQNs each vs. maintain-only and the rule-based fallback (data expansion, see
training/README.md "Data expansion (v2)" for the pre-registered criterion).

Run after training seeds 0-14 with
`train_rl_agent.py --pools v3 --mixed-rate --output-dir training/checkpoints/rl_agent_v3`:
    gateway/.venv/Scripts/python.exe training/evaluate_rl_ensembles.py [--ship]

Ensemble k is seeds 5k..5k+4, grouped before any evaluation, so no member is
picked by its results. Sessions are built from the v3 **test** pool (old test
+ the new locked test), N_SESSIONS per held-out preset, paired across
policies by seed (evaluate_rl_agent.py explains the pairing and metrics).

**Criterion (pre-registered):** GO only if all 3 ensembles, on every preset,
beat both maintain-only and the rule (paired 95% CI of the return difference
entirely above 0) and keep benign-session lockout <= the rule's + 1 point.

--ship writes one ensemble to gateway/app/core/defense/rl/dqn_policy.npz with
the verdict next to it (dqn_policy.json; SESSION_POLICY=auto runs the DQN
only on GO). The ensemble is chosen on validation sessions (v3 train pool,
seeds never used in training), never on the test results.
"""

import argparse
import json
from dataclasses import replace
from datetime import date
from pathlib import Path

import generate_sessions as gs
import numpy as np
from evaluate_rl_agent import LOCKOUT_SLACK, VALIDATION_SEED_OFFSET, metrics, paired, play, table

from app.core.defense.rl.dqn import (
    DEFAULT_WEIGHTS_PATH,
    DQNEnsemble,
    DQNPolicy,
    load_dqn,
    save_ensemble,
)
from app.core.defense.rl.fallback_policy import MaintainPolicy, RuleBasedPolicy

AGENT_DIR = gs.REPO_ROOT / "training" / "checkpoints" / "rl_agent_v3"
OUTPUT_PATH = gs.REPO_ROOT / "training" / "checkpoints" / "rl_eval_v3.json"
N_SESSIONS = 20_000
N_VALIDATION = 3_000
N_ENSEMBLES = 3
MEMBERS = 5
VALIDATION_RATES = (0.05, 0.2, 0.5)


def ensemble_files(k: int) -> list[Path]:
    files = [AGENT_DIR / f"dqn_shaping_seed{MEMBERS * k + i}.npz" for i in range(MEMBERS)]
    missing = [f.name for f in files if not f.exists()]
    if missing:
        raise SystemExit(f"missing agents in {AGENT_DIR}: {missing} - train seeds 0-14 first")
    return files


def build_ensemble(files: list[Path]) -> DQNEnsemble:
    members = []
    for f in files:
        policy = load_dqn(f)
        if not isinstance(policy, DQNPolicy):
            raise SystemExit(f"{f} is not a single agent")
        members.append(policy)
    return DQNEnsemble(members)


def validation_return(policy) -> float:
    per_rate = N_VALIDATION // len(VALIDATION_RATES)
    returns = []
    for k, rate in enumerate(VALIDATION_RATES):
        config = replace(gs.TRAIN, attack_session_rate=rate, shaping_coef=0.0)
        offset = VALIDATION_SEED_OFFSET + k * per_rate
        returns.append(metrics(play(gs.TRAIN_SPLIT, config, policy, per_rate, offset))["return"])
    return float(np.mean(returns))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ship", action="store_true")
    parser.add_argument("--sessions", type=int, default=N_SESSIONS)
    args = parser.parse_args()
    gs.use_pools("v3")

    files = {f"ensemble{k}": ensemble_files(k) for k in range(N_ENSEMBLES)}
    ensembles = {name: build_ensemble(fs) for name, fs in files.items()}
    baselines = {"maintain": MaintainPolicy(), "rule": RuleBasedPolicy()}
    passed = dict.fromkeys(ensembles, True)
    results: dict = {
        "sessions_per_preset": args.sessions,
        "ensembles": {name: [f.stem for f in fs] for name, fs in files.items()},
        "presets": {},
    }

    for preset, config in gs.HELDOUT.items():
        config = replace(config, shaping_coef=0.0)
        played = {
            name: play(gs.EVAL_SPLIT, config, p, args.sessions) for name, p in baselines.items()
        }
        rows = {name: metrics(s) for name, s in played.items()}
        comparisons = {}
        for name, ensemble in ensembles.items():
            stats = play(gs.EVAL_SPLIT, config, ensemble, args.sessions)
            m = metrics(stats)
            vs_maintain = paired(stats, played["maintain"])
            vs_rule = paired(stats, played["rule"])
            ok = (
                vs_maintain["ci_low"] > 0
                and vs_rule["ci_low"] > 0
                and m["benign_lockout"] <= rows["rule"]["benign_lockout"] + LOCKOUT_SLACK
            )
            passed[name] &= ok
            rows[name] = m
            comparisons[name] = {
                "metrics": m,
                "vs_maintain": vs_maintain,
                "vs_rule": vs_rule,
                "criterion_met": ok,
            }
        results["presets"][preset] = {"table": rows, "comparisons": comparisons}
        print(f"\n### {preset} ({args.sessions} sessions, v3 test prompts)\n")
        print(table(rows))
        print()
        for name, c in comparisons.items():
            vm, vr = c["vs_maintain"], c["vs_rule"]
            print(
                f"- {name}: vs maintain {vm['mean']:+.3f} [{vm['ci_low']:+.3f}, "
                f"{vm['ci_high']:+.3f}], vs rule {vr['mean']:+.3f} [{vr['ci_low']:+.3f}, "
                f"{vr['ci_high']:+.3f}]{'' if c['criterion_met'] else '  (criterion not met)'}"
            )

    decision = "GO" if all(passed.values()) else "NO-GO"
    results["passed"] = passed
    results["decision"] = decision
    print(f"\n## Go/no-go: {decision}")
    for name, ok in passed.items():
        print(f"- {name}: {'meets' if ok else 'does not meet'} the criterion on every preset")

    scores = {name: validation_return(e) for name, e in ensembles.items()}
    chosen = max(scores, key=scores.get)
    results["chosen"] = {"ensemble": chosen, "validation_returns": scores}
    print(f"- chosen on validation sessions: {chosen} ({scores[chosen]:.3f})")
    if args.ship:
        save_ensemble(DEFAULT_WEIGHTS_PATH, [m.layers for m in ensembles[chosen].members])
        verdict = {
            "decision": decision,
            "agent": f"{chosen}: {', '.join(f.stem for f in files[chosen])} (majority vote)",
            "evaluated": date.today().isoformat(),
            "criterion": (
                f"all {N_ENSEMBLES} ensembles beat maintain and rule (95% CI > 0) on every "
                f"held-out preset ({args.sessions} sessions each, v3 test prompts), benign "
                f"lockout <= rule + {LOCKOUT_SLACK:.2f}"
            ),
            "passed": passed,
        }
        DEFAULT_WEIGHTS_PATH.with_suffix(".json").write_text(json.dumps(verdict, indent=2) + "\n")
        shipped = DEFAULT_WEIGHTS_PATH.relative_to(gs.REPO_ROOT)
        print(f"- shipped to {shipped} with verdict {decision}")
    OUTPUT_PATH.write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
