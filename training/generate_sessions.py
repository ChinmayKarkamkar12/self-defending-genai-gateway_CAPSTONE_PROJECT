"""Synthetic sessions for the session agent (module 6b). See
project_plan/06b-adaptive-defense-rl-session-agent.md §3.

Sessions are generated on the fly by the simulator
(gateway/app/core/defense/rl/simulator.py), because an attack session
depends on what the gateway does: the attacker retries after a refusal and
stops after a breach. This file supplies what the simulator draws from:

- the prompt pools: module 5's held-out prompts with their cached
  production-classifier scores (created by training/evaluate_bandit.py).
  **val** builds the training sessions and **test** the evaluation
  sessions, so the agent is never evaluated on prompts it trained on. The
  train split isn't used: the classifier was fitted on it, so its scores
  are better than anything the gateway will see.
- the session-generator presets: TRAIN, and the held-out variants
  evaluate_rl_agent.py reports.

Run it to print what the generated sessions look like (validation of the
generator, maintain-only policy):
    gateway/.venv/Scripts/python.exe training/generate_sessions.py
"""

import json
import os
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "gateway"))
# app.config needs these to import; nothing here touches a database,
# Redis or a provider.
for _name, _value in {
    "POSTGRES_DSN": "postgresql://unused:unused@localhost:5432/unused",
    "REDIS_URL": "redis://localhost:6379/0",
    "OPENAI_API_KEY": "unused",
    "ANTHROPIC_API_KEY": "unused",
    "REDACTION_VAULT_KEY": "CsmRGHfMdzTqw8f6YCOh6vsLs9cAxgnDuoEDsPMOrw0=",
}.items():
    os.environ.setdefault(_name, _value)

from app.config import settings  # noqa: E402
from app.core.defense.rl.fallback_policy import MaintainPolicy  # noqa: E402
from app.core.defense.rl.simulator import (  # noqa: E402
    BanditDecider,
    ScoredPrompt,
    SessionSimulator,
    SimConfig,
    run_episode,
)

DATA_DIR = REPO_ROOT / "training" / "data"
TRAIN_SPLIT = "val"
EVAL_SPLIT = "test"

# What the agent trains on: 20% of sessions are attacks; benign users
# include the false-positive-prone ones.
#
# Why 20% and not the simulator's default 50%: the reward table
# (rl/reward.py) pays for *having intervened* in an attack session (+1.5
# vs -2.0) and charges for it in a benign one (-0.5 vs +1.0), whether or
# not the intervention changed anything - and tightening costs a benign
# session almost no real friction (the bias barely moves 6a's decisions).
# Intervening blind therefore pays whenever P(attack) > 0.3. A first
# 20k-step smoke run at 50% learned exactly that: it tightened 82% of benign
# sessions, most of them with no refused request at all, and lost to the
# rule at a 10% attack rate. Below 0.3, an intervention has to be earned by
# what the session does. (That smoke run was scored on test sessions; it is
# disclosed in training/README.md, and nothing else was tuned on them.)
TRAIN = SimConfig(attack_session_rate=0.2)

# Held-out evaluation, on the test split's prompts:
HELDOUT = {
    # Same generator as training, unseen prompts.
    "standard": TRAIN,
    # Base-rate shift both ways: under attack (a prior the agent wasn't
    # trained for) and quiet.
    "attack_heavy": replace(TRAIN, attack_session_rate=0.5),
    "low_attack_rate": replace(TRAIN, attack_session_rate=0.05),
    # A different world from the one trained on: longer sessions, more
    # false-positive-prone users, more probing, a more persistent attacker
    # who learns from refusals (see SimConfig.evasion_growth).
    "shifted": replace(
        TRAIN,
        min_length=5,
        max_length=25,
        fp_user_rate=0.3,
        fp_request_rate=0.4,
        max_probes=5,
        persistence=0.9,
        evasion_growth=0.1,
    ),
}


def load_pools(split: str) -> tuple[list[ScoredPrompt], list[ScoredPrompt]]:
    cache = DATA_DIR / f"bandit_scores_{split}.jsonl"
    if not cache.exists():
        raise SystemExit(
            f"{cache} is missing - run training/evaluate_bandit.py once to score the "
            "held-out splits with the production classifier"
        )
    prompts = [
        ScoredPrompt(**json.loads(line))
        for line in cache.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    benign = [p for p in prompts if not p.is_attack]
    attacks = [p for p in prompts if p.is_attack]
    return benign, attacks


def decider() -> BanditDecider:
    """Module 6a as deployed: warm-start bandit, the gateway's settings."""
    return BanditDecider(
        alpha=settings.BANDIT_ALPHA,
        allow_mask_threshold=settings.BANDIT_ALLOW_MASK_THRESHOLD,
        redact_mask_threshold=settings.BANDIT_REDACT_MASK_THRESHOLD,
    )


def simulator(split: str, config: SimConfig, seed: int = 0) -> SessionSimulator:
    benign, attacks = load_pools(split)
    return SessionSimulator(benign, attacks, config, decider=decider(), seed=seed)


def describe(split: str, config: SimConfig, n: int = 2000) -> dict:
    sim = simulator(split, config)
    stats = [run_episode(sim, MaintainPolicy().decide, seed) for seed in range(n)]
    attacks = [s for s in stats if s.label.value == "attack"]
    benign = [s for s in stats if s.label.value == "benign"]
    lengths = Counter(min(s.requests, 25) for s in stats)
    return {
        "sessions": n,
        "attack_sessions": len(attacks),
        "mean_requests": sum(s.requests for s in stats) / n,
        "attack_breach_rate": sum(s.breached for s in attacks) / max(len(attacks), 1),
        "attack_gave_up_rate": sum(s.gave_up for s in attacks) / max(len(attacks), 1),
        "attack_requests_refused": sum(s.attack_refused for s in attacks)
        / max(sum(s.attack_requests for s in attacks), 1),
        "benign_requests_refused": sum(s.benign_refused for s in benign)
        / max(sum(s.benign_requests for s in benign), 1),
        "length_histogram": dict(sorted(lengths.items())),
    }


def main() -> None:
    for name, config in {"train": TRAIN, **HELDOUT}.items():
        split = TRAIN_SPLIT if name == "train" else EVAL_SPLIT
        print(f"{name} ({split} prompts):", json.dumps(describe(split, config), indent=2))


if __name__ == "__main__":
    main()
