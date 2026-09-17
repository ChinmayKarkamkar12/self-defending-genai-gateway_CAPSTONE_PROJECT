# Self-Defending GenAI Gateway — Project Context for Claude Code

This file is read automatically at the start of every Claude Code session in this repo. It exists so you don't need to re-explain the project each time.

## What this project is

A final-year capstone project: a security proxy that sits between enterprise applications and external LLM providers (OpenAI, Anthropic), combining PII redaction, cost/usage governance, tamper-evident audit logging, and a two-tier adaptive defense layer against prompt injection/jailbreak attacks.

Two deployable pieces:
- `gateway/` — Python/FastAPI reverse proxy. Headless — no UI. Apps point their SDK `base_url` at it.
- `dashboard/` — Next.js web app. The only actual "webapp" part; a pure client of the gateway's admin API.

Team: Chinmay (ENG23DS0007), Aditya S (ENG23DS0001), Priyanka M (ENG23DS0026). Guide: Mr. Monish L.

## Full plan location

The complete module-by-module plan lives in `../project_plan/` (13 files). Start with `../project_plan/00-INDEX.md` — it explains the build order, dependencies between modules, and shared conventions in full detail. This file is a short summary; that folder is the source of truth.

Module order:
`01` repo skeleton → `02` gateway core/pipeline → `03` cost governance, `04` PII redaction, `05` threat classifier (parallel) → `06a` tactical bandit → `06b` RL session agent (**needs 06a done first**) → `07` audit logging → `08` dashboard → `09` testing → `10` deployment → `11` roadmap

## Session start/end protocol — follow this every session

1. **At the start of every session:** read `PROGRESS.md` in this repo root to see what's done, what's in progress, and any notes left for next time. If `PROGRESS.md` doesn't exist yet, create it using the template at the bottom of this file.
2. **Work from exactly one module file at a time.** I will tell you which one (e.g. "read `../project_plan/03-cost-usage-governance.md` and implement it"). Don't jump ahead to a module whose dependencies (listed at the top of each module file) aren't met yet.
3. **Follow the module file's own task list in order**, and run the tests in its "Test plan" section before considering anything done.
4. **Don't mark a module complete unless its "Definition of done" checklist genuinely passes** — actually run the commands, don't just assume.
5. **At the end of every session:** update `PROGRESS.md` — what got finished, what's partially done, and anything the next session needs to know (a blocker, a decision made, a TODO).
6. **Commit to git after finishing a module's Definition of Done**, with a message like `module 3: cost and usage governance complete`. Don't leave work uncommitted across sessions.

## Hard rules — do not deviate from these without being asked

- **6b depends on 6a.** Never start `06b-adaptive-defense-rl-session-agent.md` until `06a-adaptive-defense-bandit.md`'s Definition of Done is met — 6b reads 6a's action history and writes to its `escalation_bias` hook.
- **The adaptive defense is a hybrid, not one algorithm.** 6a is a contextual bandit (per-request, fast). 6b is genuine reinforcement learning — a DQN agent operating over sessions (sequences of requests), not over single requests. Don't collapse these into one module or call the bandit "RL" — they're different techniques solving different-shaped problems, and the distinction matters for the project's viva defense.
- **6b must have a working rule-based fallback before DQN training is attempted.** RL training instability is the biggest risk in this whole project — build the fallback first, per that module's section 6.
- **Fail-closed by default.** If any pipeline stage errors, the gateway blocks the request rather than passing it through unchecked, unless `FAIL_MODE=open` is explicitly set. See ADR-0001 (written as part of Module 2).
- **Never log or store raw PII anywhere** — not in audit logs, not in bandit/RL state, not in application logs. Only entity-type counts and redacted values. This is tested explicitly in multiple modules — treat it as a hard security boundary, not a style preference.
- **API keys and upstream provider keys are never exposed to clients or logged in plaintext.**

## Shared conventions

- Python 3.11+, FastAPI, Pydantic v2 for all request/response models
- `ruff` for lint and format (line length 100)
- `pytest` + `pytest-asyncio` + `httpx.AsyncClient` for tests
- All config/secrets via environment variables, loaded through `pydantic-settings` — never hardcoded
- One feature branch per module, PR per module
- Commit style: `<module>: <short description>`

## Tech stack

| Layer | Choice |
|---|---|
| Gateway | Python + FastAPI |
| Detection model | HuggingFace transformers (DeBERTa, fine-tuned) |
| PII detection | Microsoft Presidio |
| Tactical defense | Contextual bandit (LinUCB / Thompson Sampling) |
| Strategic defense | DQN via `stable-baselines3` |
| Structured data | PostgreSQL |
| Rate limiting / budgets / session state | Redis |
| Dashboard | Next.js + TypeScript + Recharts + Tailwind |
| Deployment | Docker Compose |

## PROGRESS.md template (create this file if it doesn't exist)

```markdown
# Build Progress

## Completed modules
(none yet)

## In progress
(none yet)

## Not started
- [ ] Module 1: Repo & conventions
- [ ] Module 2: Gateway core proxy
- [ ] Module 3: Cost & usage governance
- [ ] Module 4: PII redaction
- [ ] Module 5: Threat detection classifier
- [ ] Module 6a: Adaptive defense — tactical bandit
- [ ] Module 6b: Adaptive defense — RL session agent
- [ ] Module 7: Audit logging
- [ ] Module 8: Admin dashboard
- [ ] Module 9: Testing strategy
- [ ] Module 10: Deployment
- [ ] Module 11: Build roadmap (reference only, not implemented)

## Notes for next session
(none yet)
```
