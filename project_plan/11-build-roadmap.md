# Module 11: Build Roadmap — Week-by-Week Sequencing

**Purpose:** map the 10 module files to an actual semester timeline with a 3-person team, and flag the faculty checkpoints. Adjust week numbers to your actual academic calendar — the sequencing and parallelization logic is what matters, not the literal week numbers.

## Team split (3 people)

Given modules 3, 4, and 5 have no dependency on each other once module 2 exists, this is the natural three-way parallel split:
- **Person A (owns cost/governance path):** Module 3, then Module 6a (bandit consumes module 5's output — adjust based on who's stronger in ML vs. backend)
- **Person B (owns data-protection path):** Module 4, then contributes to Module 7 (audit logging touches every module's output, good integration point for whoever has the most cross-module context by that point)
- **Person C (owns ML/detection path):** Module 5 (the classifier — likely the person with the most ML/data-science background given your DeBERTa/RAPIDS/GPU tooling experience), then Module 6b (the RL agent — same reasoning, this is the module needing the most ML depth; Person A and C should pair on the 6a→6b handoff since 6b consumes 6a's output directly)

Module 1 and 2 are foundational — build these together as a team in week 1, don't split them, since every later module depends on getting the interfaces right.
Module 8 (dashboard) is a good place for whoever's least loaded once their backend module stabilizes — it can start early against mocks (see module 8's task 2) and doesn't need to wait for everyone else to finish.

## Timeline

| Weeks | Focus | Modules | Milestone |
|---|---|---|---|
| 1 | Foundations, together | 1, 2 | Health endpoint + auth + pipeline stub wiring works; ADR-0001 written |
| 2–4 | Parallel core modules | 3, 4, 5 (one owner each) | Each module's own Definition of Done met independently, tested against module 2's stubs |
| 3–5 (overlaps above) | Dashboard scaffold, against mocks | 8 (tasks 1–3 only) | Dashboard shell + first 2 screens render against mock data |
| 5 | **Faculty checkpoint 1** | — | Demo: gateway proxies real requests, redaction + threat scoring both work independently |
| 5–6 | Tactical layer | 6a (bandit) | Modules 3, 4, 5 wired into the real pipeline together; bandit built and evaluated against static-threshold baseline — 6a's Definition of Done fully met |
| 6–8 | Strategic layer | 6b (RL agent) | Simulator + rule-based fallback built first (de-risks immediately); DQN training attempted against the go/no-go checkpoint below |
| **end of week 7** | **RL go/no-go checkpoint** | 6b, section 6 | If `evaluate_rl_agent.py` doesn't show clear, reproducible improvement over baseline by this date, activate the rule-based fallback and document the attempt — don't let RL training uncertainty threaten the rest of the timeline |
| 6–8 | Audit + dashboard catch-up | 7, 8 (remaining screens) | Tamper-evidence demo works; dashboard fully wired to real APIs |
| 8 | **Faculty checkpoint 2** | — | Demo: full pipeline end to end, dashboard shows live data, bandit-vs-baseline numbers ready, RL vs. baseline vs. fallback comparison ready (whichever policy is active) |
| 9 | Cross-cutting hardening | 9 | Full-pipeline + security boundary tests all green; CI enforced |
| 9–10 | Deployment polish | 10 | Clean-machine bring-up verified; demo script rehearsed at least twice |
| 10–11 | Buffer + report writing | — | Slack for whatever's behind; write up the evidence base, architecture, and evaluation numbers into the final report |
| 12 | **Final presentation** | — | Live demo per `docs/DEMO_SCRIPT.md` |

## Risk flags — watch these specifically

- **Module 5 (classifier training) is the most likely to run over.** Fine-tuning + dataset prep + evaluation has more variance than the backend modules. If it's slipping by week 4, cut scope: fewer attack classes (2-class benign/attack instead of 3-class), smaller base model, or fewer training epochs — document the trade-off rather than silently shipping something untested.
- **Module 6a (bandit) depends on module 5 being stable first.** Don't start the bandit's context-feature wiring against a classifier that's still changing its output shape — that's wasted rework. Confirm module 5's `ThreatScore` schema is frozen before starting 6a's `features.py`.
- **Module 6b (RL agent) is the single highest-risk module in this plan.** DQN training instability is real and has no guaranteed timeline. This is exactly why 6b's plan has you build the rule-based fallback *before* attempting DQN training, and has an explicit go/no-go checkpoint (see the timeline table above) — if training isn't converging by that date, ship the fallback and document the RL attempt honestly in the report rather than letting it consume time meant for modules 7–10.
- **Don't let module 8 (dashboard) become a week-11 scramble.** It's the only thing faculty directly interacts with in a demo — starting it early against mocks (as scoped in its own file) is there specifically to prevent this.

## What to explicitly NOT attempt this semester

State this plainly in your report rather than letting it surface as a gap during questions:
- The adversarial red-team retraining loop (module 6a, section 11) — real but explicitly out of scope unless everything else finishes early, including 6b's RL agent
- Multi-region/HA deployment — Docker Compose only
- A second, third, fourth LLM provider beyond OpenAI + Anthropic — the adapter pattern (module 2) supports adding more, but building only two is enough to prove the pattern works
