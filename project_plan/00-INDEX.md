# Self-Defending GenAI Gateway — Project Plan Index

**Team:** Chinmay (ENG23DS0007), Aditya S (ENG23DS0001), Priyanka M (ENG23DS0026)
**Type:** Final-year B.Tech CSE (Data Science) major project
**Status:** Planning complete, implementation not started

---

## How to use this plan with Claude Code

This plan is deliberately split into one file per module instead of one giant document. Feed Claude Code **one file at a time**, in build order, as a separate task/session per module. Each module file is self-contained: it restates its own purpose, its dependencies on earlier modules, and its own test plan, so Claude Code doesn't need the whole plan in context to work on it correctly.

Recommended workflow per module:
1. Open a fresh Claude Code session (or `/clear` context).
2. Paste or reference only that module's `.md` file.
3. Ask Claude Code to implement the tasks in order, running the listed tests after each task.
4. Don't move to the next module file until the current one's "Definition of done" checklist is fully green.

Do not paste multiple module files into one session — that's exactly the confusion this split is meant to avoid.

---

## Module files, in build order

| # | File | What it builds | Depends on |
|---|---|---|---|
| 1 | `01-repo-and-conventions.md` | Repo skeleton, shared conventions, env config | none |
| 2 | `02-gateway-core-proxy.md` | FastAPI reverse proxy, auth, provider routing | 1 |
| 3 | `03-cost-usage-governance.md` | Budgets, rate limiting, token accounting | 1, 2 |
| 4 | `04-pii-redaction.md` | Presidio + regex PII detection/masking | 1, 2 |
| 5 | `05-threat-detection-classifier.md` | Prompt injection/jailbreak ML classifier | 1, 2 |
| 6a | `06a-adaptive-defense-bandit.md` | Tactical layer — contextual bandit, per-request | 1, 2, 5 |
| 6b | `06b-adaptive-defense-rl-session-agent.md` | Strategic layer — RL session agent (DQN) | 1, 2, 5, **6a must be done first** |
| 7 | `07-audit-logging.md` | Hash-chained tamper-evident logging | 1, 2, 3, 4, 5, 6a, 6b |
| 8 | `08-admin-dashboard.md` | Next.js dashboard (policies, logs, analytics) | 1–7 (consumes their APIs) |
| 9 | `09-testing-strategy.md` | Cross-cutting test strategy, CI, coverage targets | all |
| 10 | `10-deployment-docker-compose.md` | Docker Compose demo environment | all |
| 11 | `11-build-roadmap.md` | Week-by-week schedule, milestones, faculty checkpoints | all |

The dependency column tells you what must already exist and be working before starting that file. Modules 3, 4, and 5 don't depend on each other — the three of you can build them in parallel once module 2 (the core proxy) exists, one person per module. **6a and 6b are sequential, not parallel** — 6b's RL agent consumes 6a's bandit action history as part of its state, so 6a's Definition of Done must be met before starting 6b.

The adaptive defense layer is a hybrid, matching the RL agent design (state/action/reward/training environment) already specified in the submitted proposal: **6a** is a fast per-request contextual bandit, **6b** is a reinforcement-learning agent operating over sequences of requests within a session, adjusting 6a's thresholds based on session-level patterns. See `06b`, section 1, for why the sequential/session framing is where RL genuinely fits, as opposed to being forced onto single isolated requests.

---

## System shape, restated briefly

Two deployable pieces:
1. **Gateway** (`gateway/`) — a Python/FastAPI backend service. Not a webapp — it's an inline reverse proxy that client apps point their OpenAI/Anthropic SDK `base_url` at.
2. **Dashboard** (`dashboard/`) — a Next.js webapp. This is the actual "webapp" part of the project, and it's purely a client of the gateway's admin API.

Request pipeline order inside the gateway (cheapest checks first):
`auth + budget check → threat detection → PII redaction → forward to provider → output scan → async audit log`

---

## Shared conventions (apply across every module)

- **Language/framework:** Python 3.11+, FastAPI, Pydantic v2 for all request/response models
- **Package manager:** `uv` or `pip` with `requirements.txt` — pick one and stay consistent
- **Formatting/linting:** `ruff` for both lint and format
- **Testing:** `pytest` + `pytest-asyncio`, `httpx.AsyncClient` for API tests
- **Config:** all secrets/config via environment variables, loaded with `pydantic-settings`, never hardcoded
- **Git:** one feature branch per module file, PR per module, don't merge until that module's Definition of Done is met
- **Commit style:** `<module>: <short description>` e.g. `pii: add credit card regex detector`

## Definition of done, applied to every module

A module is not done until:
- [ ] All tasks in its file are implemented
- [ ] All tests in its test plan pass
- [ ] It runs standalone via the module's own quick-start command
- [ ] It's wired into the gateway pipeline (if applicable) and doesn't break earlier modules' tests
