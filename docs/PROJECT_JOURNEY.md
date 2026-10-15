# Project Journey — Self-Defending GenAI Gateway

The story of how this project was built, what went wrong, how it was fixed,
and how it improved, with the numbers. Written for the viva and interviews.

Everything here comes from the project's own records: `PROGRESS.md`,
`LIMITATIONS.md`, `training/README.md`, `docs/adr/`, and the git log. Where a
number is quoted, the detailed source is named so it can be checked.

Team: Chinmay (ENG23DS0007), Aditya S (ENG23DS0001), Priyanka M (ENG23DS0026).
Guide: Mr. Monish L.

---

## 1. The project in one paragraph

Companies want to use LLMs (OpenAI, Anthropic), but sending prompts straight to
a provider is risky: users paste personal data, attackers try prompt injection
and jailbreaks, and costs can run away. This project is a **security proxy**
that sits between a company's apps and the LLM provider. An app changes one
setting (its SDK `base_url`) to point at the gateway, and every request then
passes through a pipeline that checks the budget, scores the prompt for
attacks, removes personal data (PII), decides what to do with risky requests
(allow, redact, block, or send to a human), and watches whole sessions for
attackers who keep trying. Everything is recorded so the decisions can be
audited.

## 2. What happens to one request

```
App ──► Gateway ──────────────────────────────────────────────► LLM provider
          │
          ├─ auth            API key checked (SHA-256 hash lookup)          [module 2]
          ├─ session_guard   is this key locked out? which session is it?   [module 6b]
          ├─ budget_check    reserve the estimated cost atomically (Redis)  [module 3]
          ├─ threat_detection  DeBERTa classifier scores the prompt         [module 5]
          ├─ pii_redaction   Presidio + regex remove PII                    [module 4]
          ├─ bandit_policy   allow / redact / block / escalate              [module 6a]
          ├─ session_policy  RL agent or rule: tighten, challenge, lockout  [module 6b]
          │
          │   ...provider answers...
          │
          ├─ usage_recording real cost recorded, reservation reconciled     [module 3]
          ├─ output_scan     did the answer leak the system prompt?         [module 5]
          ├─ defense_feedback  leaks become a learning signal for 6a        [module 6a]
          │
          └─ audit_log       one hash-chained receipt, on EVERY exit path   [module 7]
                             (allowed, blocked or failed), written in the
                             background after the response has gone

```

If any stage crashes, the request is **blocked** (fail-closed, ADR-0001).

## 3. Timeline

| Date | What happened | Commits |
|---|---|---|
| 2026-08-27 | Plan written; module 1 (repo, config, health endpoint, CI) | `9df7104`..`8fba9b3` |
| 2026-09-07 | Module 2: the proxy itself (auth, pipeline, OpenAI/Anthropic routing) | `7b40922` |
| 2026-09-17 | Module 3: budgets and rate limits; a race condition found and fixed | `a439743`..`3e16d38` |
| 2026-09-17 | Module 4: PII redaction; security audit with 4 fixes | `54ba957`..`1fd73b5` |
| 2026-10-07 | Module 5: threat classifier; data leakage found and fixed, retrained | `c94e46f`..`eb52015` |
| 2026-10-07 | Module 6a: contextual bandit | `cce8e44`, `168b7dd` |
| 2026-10-10 | 6a hardening pass (16 gaps checked, 10 fixed) | `18beb09`..`271d483` |
| 2026-10-10 | Module 6b: RL session agent, two training runs, both NO-GO | `6236a89`..`5a94307` |
| 2026-10-12 | Data expansion started: 4x more training data, new locked test set | `7c026df`, `ca6f872` |
| 2026-10-13 | Classifier v2 shipped as a recorded override; RL v3 NO-GO | `9897a4e`..`c124640` |
| 2026-10-13 | Module 7: tamper-evident audit log (hash chain, trigger, tamper demo) | see PROGRESS.md |
| 2026-10-14 | Module 7 review: 5 fixes incl. 3x faster gateway; optional Ollama provider and first real end-to-end run; streaming rejected | `18eadc2`..`9486c01` |
| 2026-10-14 | Module 8: admin login, the "checkpoint" dashboard (6 screens), 61 dashboard tests, Docker, CI | `ae68574`..`4291bab` |

---

## 4. Module by module

### Module 1 — Repo skeleton

- **Goal:** a clean starting point everyone can run.
- **Built:** FastAPI app with `GET /health`, settings loaded from environment
  variables through `pydantic-settings` (never hardcoded), Docker Compose,
  `ruff` linting, `pytest`, GitHub Actions CI.
- **Checked:** `docker compose up` works, `/health` returns 200, a missing
  `.env` fails loudly instead of starting with bad config.

### Module 2 — Gateway core proxy

- **Goal:** accept OpenAI-style requests and forward them to the right provider.
- **Built:**
  - API-key auth: keys are stored only as SHA-256 hashes.
  - A **fixed-order pipeline** of stages. Each stage returns ALLOW, MODIFY or
    BLOCK. Later modules plug their logic into these stages.
  - Provider adapters: `gpt-*` goes to OpenAI, `claude-*` to Anthropic (with
    the request translated to Anthropic's format).
  - Postgres tables for teams and API keys, with alembic migrations.
- **Key decision — fail-closed (ADR-0001):** if a stage crashes (e.g. Redis is
  down), the request is blocked with a 503. The alternative, fail-open, would
  let an attack through whenever a security check broke. `FAIL_MODE=open`
  exists only as an explicit opt-in for local development.
- **Problem found:** inside Docker, the gateway tried to reach Postgres at
  `localhost`, which inside a container means itself. Fixed by pointing the
  container at the service names (`postgres`, `redis`) and adding health checks
  so the gateway waits for the database.

### Module 3 — Cost and usage governance

- **Goal:** teams get budgets and rate limits; every request's cost is recorded.
- **Built:** token-bucket rate limiter (a Lua script in Redis, so it is atomic),
  per-team budgets, a pricing table, token counting with `tiktoken`, admin
  endpoints for usage and budgets.
- **Problem found and fixed — a race condition (`14ecc63`):** the first version
  read the spend, compared it to the limit, then allowed the request. Ten
  requests arriving together could all read "under budget" before any of them
  recorded its cost, so the limit could be overshot. Fixed with
  **reserve-then-reconcile**: one atomic Redis script reserves the estimated
  cost and checks the limit in the same step; after the provider answers, the
  reservation is corrected to the real cost; if the request fails anywhere,
  the reservation is refunded. Test: 10 concurrent requests against a budget
  for 3 → exactly 3 allowed, also verified against real Redis.
- **Second bug, found by a test, not by reading the code (`2ae91bb`):** the
  reservation info was removed from the request before reconciliation finished,
  so if reconciliation itself failed, the refund handler found nothing to
  refund and the money "leaked". Fixed by removing it only after success.
- **Another fix:** a model missing from the pricing table used to turn a
  successful answer into a 503. Now the answer is returned and the cost is
  logged as $0 with a warning.

### Module 4 — PII redaction

- **Goal:** personal data never reaches the provider, and is never stored raw.
- **Built:** Microsoft Presidio (with spaCy) for names, emails, phones etc.,
  plus our own regex layer for API keys (`sk-...`, `AKIA...`) and credit cards
  (Luhn-checked). Two modes: **mask** (`[REDACTED_EMAIL_ADDRESS]`) or
  **tokenize** (a random token; the original is stored encrypted with Fernet).
  Only entity-type counts are ever logged, never values.
- **Decision:** redaction is on for every team by default, even with no policy
  configured. Budgets are opt-in; privacy protection is not.
- **Security audit, four findings, all reproduced before fixing (`1fd73b5`):**
  1. When the regex layer and Presidio both matched the same credit card with
     the same score, the winner was arbitrary. Now a documented rule: exact-format
     regex matches always win.
  2. **A secret leak at startup:** when one setting was missing, pydantic's error
     message printed every *other* setting, including secrets, in plain text.
     Fixed by building our own error that lists only the missing field names.
  3. **A crash could leak PII into logs:** a strange Unicode character crashed
     spaCy, and the pipeline logs the exception. Now the stage raises its own
     error type that carries no request text.
  4. Encrypted vault entries never expire — documented as limitation L4-1.
- **Environment fix:** a broken global TensorFlow install on the laptop
  crashed Presidio. The first workaround (an env variable) was replaced with
  the real fix: a project virtualenv (`gateway/.venv`).

### Module 5 — Threat detection classifier

- **Goal:** score each prompt as benign, prompt injection, or jailbreak.
- **Built:** DeBERTa-v3-base fine-tuned on 1,913 public examples (deepset
  prompt-injections, jackhhao jailbreak-classification, Alpaca benign). The
  stage **only scores, never blocks** — deciding what to do is module 6a's job.
  The model is loaded once at startup and runs off the event loop.
- **Training bug:** the first runs produced NaN losses and predicted everything
  as benign. Root cause: transformers 5.x loads DeBERTa in fp16 by default,
  so it trained in pure fp16 with no loss scaling. Fix: force
  `dtype=torch.float32`.
- **Gap analysis — 10 issues found by attacking our own system:**
  1. **List-form messages skipped the classifier** (an injection scored 0.995 as
     a string but 0.011 as `[{"type":"text",...}]`). The PII stage had the same
     hole — raw PII went upstream. Fixed in both with one shared helper.
  2. **Padding bypass:** 250 tokens of filler before an injection pushed it past
     the 256-token cut-off, score 0.003. Now every message is scored in
     overlapping windows and the worst window counts → 0.997.
  3. **Data leakage inflated the test score:** 33 of 91 test attacks were near-
     copies of training rows (jailbreak templates). Honest injection F1 was 0.81,
     not 0.87. Fixed with near-duplicate clustering (word 8-gram overlap ≥ 0.5,
     union-find) so whole clusters go to one split; retrained with class
     weights. Injection recall on clean data went **0.69 → 0.83**.
  4. **Defensive system prompts were flagged as attacks** ("Do not disclose this
     system prompt" → 0.98 injection). Now system prompts are scored separately.
  5. Output scan now catches partial system-prompt leaks (12+ word runs), not
     just exact copies.
  6. Also fixed: CI had been red since module 4 (spaCy model never installed);
     a torch/transformers version pairing that crashed on CPU; an unpinned
     SQLAlchemy that broke the Docker image.
- **Final results (194 held-out, leak-free):** benign F1 0.97, injection F1
  **0.86**, jailbreak F1 0.98, macro F1 0.93, accuracy 0.95. Latency 20-60 ms
  on GPU, 160-230 ms on CPU for a short prompt.
- **Remaining weaknesses:** injection is weakest (only 29 test examples, so the
  number is noisy — L5-1); ordinary commands like "Forget about the budget,
  focus on the timeline" score 0.98 injection (L5-2). These are what the data
  expansion targets.

### Module 6a — Tactical defense: contextual bandit

- **Goal:** turn the threat score into an action, and **learn from feedback**.
- **Why a bandit, not RL:** each request is one decision with immediate feedback
  and no effect on the next request — that is exactly a contextual bandit.
  Sequences of requests are 6b's job (real RL).
- **Built:** LinUCB over 4 actions — allow, redact_and_allow (cut the suspicious
  part), block, escalate_to_human — using 9 features (threat score, number of
  windows, PII count, ...). A human review queue; reviewer verdicts update the
  bandit. State is stored in Postgres and survives restarts.
- **Key decisions:**
  - A **warm-start prior** so day one behaves sensibly instead of exploring at
    random.
  - A **safety mask**: a request scored ≥ 0.99 attack can never be allowed,
    whatever was learned.
  - The reward table was changed from the plan's draft because the draft made
    redact and escalate never optimal ("dead arms").
  - The stage runs *after* PII redaction, so the review queue never sees raw PII.
  - Found while coding: Python's `max(0.0, nan)` is `0.0`, so a NaN score would
    have counted as "benign" (fail-open). NaN now raises.
- **Honest result:**
  - On normal data the bandit **ties** a hand-tuned threshold (0.721 vs 0.719).
    Why: the classifier's scores are bimodal (almost everything is ~0 or ~1),
    so there is nothing in the middle to learn from.
  - Under simulated **false-positive drift** it clearly wins: **+0.141 reward per
    request** with full feedback, and benign refusals drop from 21% to 0.9%.
    At the realistic 2% review rate the gain is +0.042.
  - Viva line: *the bandit costs nothing where the classifier is right and
    recovers where it drifts, but it can't fix the classifier's blind spots.*
- **Hardening pass (2026-10-10, `18beb09`):** 16 gaps checked with probe scripts,
  10 fixed. Examples: one unauthenticated Redis write could make the bandit
  allow p=0.6 attacks (bias now clamped to [-0.3, 1.0]); attacker-controlled
  features (request rate, time of day) could flip decisions (removed); old
  feedback never faded (now discounted, drift recovery 793 → 144 labels);
  verdicts can be amended; the review queue is capped per team. An ablation
  showed about half of the 2% gain came from dropping the noisy features — an
  earlier claim that credited discounting was wrong and was corrected.

### Module 6b — Strategic defense: RL session agent

- **Goal:** watch a whole session (a sequence of requests from one API key) and
  react to attackers who keep trying — real reinforcement learning, since each
  action changes what happens next.
- **Measured before building:** the plan's lever (making 6a stricter) only
  changes decisions for ~1% of traffic, and 8/190 attacks score below 0.2 —
  invisible to any score-based rule. So the agent needed new actions:
  **challenge** (force the next request to human review) and **lockout**
  (refuse the key for 15 minutes; admin can unlock). The user approved
  widening the contract.
- **Built:** session tracking in Redis, a **rule-based fallback built first**
  (tighten after 2 refusals, lock out after 4), a simulator that uses 6a's real
  decision code and real held-out prompts, and a DQN (stable-baselines3) whose
  weights run in the gateway as plain numpy — no pickle.
- **Go/no-go criterion, written before training:** at least 4 of 5 seeds must
  beat both "do nothing" and the rule (95% CI) on every test scenario, and must
  not lock out more benign sessions than the rule + 1 point.
- **Run 1 — NO-GO (2/5 seeds).** The DQN won on reward and cut breaches
  (10.2% vs the rule's 14.4%), but 3 seeds did it by wrongly locking out 2-5x
  more innocent sessions. Without reward shaping 2 seeds collapsed. Surprise:
  potential-based shaping made training much more stable.
- **Run 2 — fixes aimed at run 1's measured failures:** wrongful lockout now
  costs -2.0; lockout needs 2 refusals; checkpoints chosen on validation;
  added `SESSION_POLICY=auto` (use the DQN only if a verdict file says GO).
- **Run 2 — NO-GO again (3/5).** Safety fixed (benign lockout 0.9% vs rule
  0.8%), breaches 9.9% vs 14.4%. The misses: 2 seeds weren't *provably* better
  than doing nothing when only 5% of sessions are attacks — a statistical
  power problem, since the test pool had only ~4 blind-spot attacks.
- **Decision:** stop there — a third run on the same test set would turn it
  into a tuning set. The rule stays the default; the DQN is opt-in.
- Viva line: *RL found the session-memory effect the rule can't, but not
  reliably enough to be the default; the reward and the data are the
  bottleneck, not the algorithm.*

### Data expansion (v2) — 2026-10-12 to 2026-10-13

- **Why:** the three weak results above all trace back to too little data:
  injection F1 measured on only 29 examples, false positives on ordinary
  commands, and too few blind-spot attacks to judge the RL agent.
- **Rules set first:** a new test set was **locked** (SHA-256 recorded) and all
  pass/fail criteria were written into `training/README.md` *before* any model
  was trained (commit `7c026df`).
- **Data:** added neuralchemy (Apache-2.0), in-the-wild jailbreaks (MIT),
  NotInject hard-benign prompts (MIT), Dolly (CC-BY-SA). Rejected: SPML (its
  "attack" label means off-topic), two sets with no licence, one unlabelled.
  Near-duplicates removed against v1; 369 template copies dropped.
- **Size:** train 1,523 → **6,307** rows (injection examples 203 → 1,661);
  new locked test 950 rows (292 injections, vs 29 before).
- **Classifier v2 passes only if:** better injection F1 on the new test, no rise
  in benign false positives, and no real drop on the old test.
- **RL v3 passes only if:** 3 independent 5-agent voting ensembles all beat both
  baselines on every scenario with 20,000 sessions each, within the lockout
  limit. Then `auto` would switch to the DQN by itself.
- **v2 result (2026-10-13): failed, v1 stays.** v2 was far better on the new
  test (macro-F1 0.908 vs v1's 0.490; v1 flagged 27% of benign prompts and
  missed 77% of injections there). But it slipped on the old test (macro-F1
  0.884, below the 0.913 floor). Two of the three criteria passed; the rule
  needs all three, so v1 stayed. The real lesson: **v1's original 0.933 did
  not generalise**; it was measured on a small, narrow test set.
- **v3 attempt (pre-registered after seeing v2, and disclosed as a second
  look):** aimed at v2's one failure, which was forgetting the v1-style data.
  Changes: start from v1's weights, show v1 rows twice, a lower learning rate,
  2 epochs, and the epoch chosen on validation only. Same three criteria,
  unchanged. A small script (`training/apply_classifier_criteria.py`) applies
  the criteria mechanically; it was committed before v3 had any results.
- **Engineering hiccups:** a power cut killed the first v2 run. Two v3 runs
  were then killed by a low-memory guard while writing a 1.5 GB optimizer
  checkpoint. Fix: `--save-only-model` (save the weights only), and run the
  training as a detached process.
- **v3 result: failed as well**, and worse than v2 on both tests (old-test
  macro-F1 0.871, new 0.877). Per the rules, v1 would stay.
- **Override (a team decision, recorded as one):** we shipped v2 anyway.
  The rule was protecting a 194-row benchmark on which v2 misses 6 more
  attacks than v1. On the 950-row locked test, v1 flags 27.5% of benign
  prompts. Across both tests v2 misses 28 of 498 attacks (v1: 63) and flags
  18 of 646 benign prompts (v1: 151). The README says plainly that this is
  an override, not a pass.
- **6a re-check:** still a tie on normal data. New: with realistic feedback
  the bandit now trails a tuned threshold at low attack rates. Calibrated
  scores fall in the prior's middle bands, which v1's all-or-nothing scores
  never reached (L6a-30). Diagnosed on validation only.
- **RL v3: NO-GO for the third time.** 3 ensembles × 5 DQNs, 20,000 sessions
  per scenario. They beat the rule on 3 of 4 scenarios (breaches 8.3% vs
  11.7%), but lock out 3.1–3.5% of benign sessions against a 2.2% limit.
  Cause found: checkpoint selection measured lockout on only 600 sessions,
  so it picked checkpoints that looked safe by luck (the winner's curse).
  `auto` keeps the rule.
- **Lessons:** (1) a bigger test can show that an earlier "good" number
  didn't generalise (v1: 0.933 → 0.490); (2) better-calibrated inputs can
  expose assumptions downstream that were silently tuned to the old model;
  (3) a safety constraint needs as much statistical power as the objective
  it constrains.

---

### Module 7 — Tamper-evident audit logging — 2026-10-13

- **Goal:** one receipt per request recording what every module decided
  (cost, PII counts, threat score, the bandit's action, the session agent's
  action, the outcome), stored so that nobody, not even a database admin, can
  quietly change it.
- **The idea in one line:** each receipt stores the SHA-256 hash of *its own
  contents plus the previous receipt's hash*. Change any old receipt and its
  hash stops matching, and the next receipt no longer links to it. `verify`
  walks the chain and names the first broken entry.
- **Gap found before building:** the audit stub only ran on the *success*
  path. Every blocked attack, budget refusal and lockout would have been
  missing from the audit log, which is exactly what an auditor wants to see.
  The chat endpoint was restructured so every exit path is audited (approved
  by Chinmay before implementation).
- **Three layers (ADR-0002):** an ORM guard (the app can't update or delete an
  entry), a Postgres trigger (nobody can, unless they're a superuser who turns
  it off), and the hash chain (catches the superuser too).
- **Logging adds no waiting:** the request only drops the entry into an
  in-memory queue; one background worker chains and writes it. Measured A/B on
  Postgres: no meaningful latency difference. Writer: ~940 entries/s.
- **Things found by checking instead of assuming:**
  - The in-memory SQLite test DB gives every session the **same connection**:
    a probe showed one session's commit also committing another's pending
    insert. Tests moved to a per-test SQLite file in WAL mode.
  - SQLAlchemy's pool `TimeoutError` is **not** Python's `TimeoutError`; the
    writer would have dropped entries when the pool was busy. Fixed and tested.
  - `echoed_redaction_tokens` is a list, not a count. The first draft would have
    crashed on any response that echoed a token.
  - The first real-Postgres load test exposed a **module 2 bottleneck**: a new
    HTTPS client per upstream call, ~300 ms of certificate loading that
    blocks the event loop, so about 3 requests/s. Profiled, measured and
    recorded as L2-2, not silently fixed inside module 7.
- **Live:** in the Docker stack, the trigger rejected UPDATE/DELETE/TRUNCATE
  from psql, real requests (benign, PII, injection, bad model) were all
  audited with no raw PII anywhere, and `tamper_demo --postgres` caught a
  "block -> allow" edit, named the entry and restored it. After a gateway
  restart the chain continued from the database head.
- **Honest limits:** a crash loses whatever is still queued (L7-1); deleting
  the *newest* entries leaves a valid chain, so `verify` reports count and
  head hash for outside comparison (L7-2); no retention pruning (L7-4).
- Viva line: *the trigger makes the log hard to change; the hash chain makes
  any change visible, even by the person who can switch the trigger off.*
- **Follow-up work on 2026-10-14** (review fixes, Ollama, streaming): see the
  next section, "Changes made after module 7".

### Changes made after module 7 — 2026-10-14

Before moving to module 8, the whole of module 7 was re-checked against its
plan and run again (tests *and* the live Docker stack), instead of trusting
the notes from the day before. Every change below has a test that fails on
the old code and passes on the new code.

| # | What changed | Why (what was wrong) | How it was fixed | Proof | Commit |
|---|---|---|---|---|---|
| 1 | **Gateway speed (L2-2)** | For *every* request the gateway built a new HTTPS client, which loads the security certificates (~0.3 s) and freezes the whole server meanwhile. Result: only ~3 requests/second; 20 users at once waited ~7.4 s each; 100 at once crashed the database pool | One long-lived HTTPS client per provider, opened when the gateway starts and closed when it stops (`UpstreamClient` in `providers/base.py`, wired in `main.py`) | Live: 20 at once ~7.4 s → ~2.6 s each; 100 at once all completed; ~9 req/s | `18eadc2` |
| 2 | **Bad provider replies** | If a provider answered "200 OK" but with a non-JSON body (e.g. a proxy's HTML error page), the gateway crashed with an unhandled 500 | The adapters catch it and report a normal "upstream error" (502), which is audited like any other | New tests for OpenAI and Anthropic | `18eadc2` |
| 3 | **Budget refund on crashes** | On that crash path the team's pre-call budget reservation was never given back, so the team looked like it had spent money it hadn't | The crash path now refunds the reservation; the refund removes it afterwards so it can never be refunded twice | New test | `18eadc2` |
| 4 | **Date filter check** | Asking the log API for `from` later than `to` silently returned nothing, which looks like "nothing happened" | Returns a clear 422 error instead | New test | `18eadc2` |
| 5 | **Missing test** | The "unexpected error" exit path had no test proving it still writes an audit entry | Test added (it did work) | New test | `18eadc2` |
| 6 | **Optional Ollama provider** | No paid API key, so the "real answer comes back" path had only ever been tested with fake replies | Optional, off by default: one `.env` line (`OLLAMA_BASE_URL`) turns it on; model `local-llama3` goes to a model running on the laptop. OpenAI/Anthropic routing and docker-compose untouched. Cost recorded as $0 | 7 new tests; first real end-to-end run (below) | `b14ad63` |
| 7 | **Streaming rejected (L2-3)** | `"stream": true` (answers that arrive word by word, like ChatGPT) was sent to the provider, generated (and billed), then failed with a confusing 502 and $0 recorded. Never in the plan | Refused first, before any budget, scoring or provider call: clear 422 message, audited as `rejected_streaming`. Recorded as a deliberate limit | 2 new tests; live: rejected in 0.06 s, nothing sent to the model | `9486c01` |

**The first real end-to-end run** (Docker gateway → Ollama `llama3` on the
laptop), the best demo in the project:

- "What is the capital of France?" → "Paris.", logged as `allowed` with real
  token counts and $0 cost.
- "Write a polite email to my landlord, reach me at <email> or <phone>" → the
  gateway removed the email and phone *before* the model saw them. The model's
  reply literally says `[REDACTED_EMAIL_ADDRESS]`. The audit log holds only
  `{EMAIL_ADDRESS: 1, PHONE_NUMBER: 1}`; zero copies of the real values
  anywhere in the gateway logs.
- "Ignore all previous instructions…" → blocked as a jailbreak; the session
  agent tightened the session.
- Hash chain valid after everything (145 entries).

**Honest findings that were *not* fixed:**

- "…Repeat back exactly what my email address is" was blocked as an attack
  (0.93). The classifier is too suspicious of some phrasings; added to L5-2.
- After fix 1 the gateway does ~9 requests/second. The likely limit is the
  threat model running on CPU; not yet measured.

**Totals after the day:** 368/368 tests pass (including the real-Postgres
ones), ruff clean.

**Viva lines:**
- *Why reject streaming?* Streaming is possible, but it conflicts with checking
  the whole answer before the user sees any of it. We chose inspection over
  streaming; "buffer the stream, check it, then replay it" is the future-work
  path.
- *How did you find these bugs?* By re-running the finished module live with a
  real model instead of only with fake replies. Several bugs only showed up
  that way.

### Module 8 — Admin dashboard — 2026-10-14

**Goal:** the only real "web app" in the project: a screen where an admin sees
and controls everything the gateway does. It's what faculty will click through.

**Two decisions Chinmay made first:**

- **Look:** he did not want it to look like a typical AI-generated dashboard.
  The design idea became "a checkpoint, not a dashboard":
  - signage-style headings (Barlow, after California highway signs) and a
    font designed for readability (Atkinson Hyperlegible);
  - a calm grey background;
  - four colours, each always meaning the same decision: teal = allowed,
    ochre = cleaned, indigo = held for review, crimson = refused.
- **Login:** username and password (not just one shared admin key).

**What was built, why, and how:**

| # | What | Why | How | Proof | Commit |
|---|---|---|---|---|---|
| 1 | **Admin login on the gateway** | Every `/v1/admin` route was open to anyone (L3-1, L6a-4, L7-7): anyone could read the audit log, change budgets or forge review verdicts | `admin_users` table with scrypt password hashes; login returns a random token, and Redis stores only its hash for 8 h; 5 wrong passwords lock the username for 15 min; the login check is attached once to every admin router, and a test walks all admin endpoints | 22 new gateway tests; live: 401 without login, logout kills the token | `ae68574` |
| 2 | **Reviewer = the logged-in admin** | The verdict API took the reviewer's name from the request, so anyone could sign a verdict as someone else | The name now comes from the session; the field was removed | Test with two different admins amending | `ae68574` |
| 3 | **Summary endpoints** | The plan says the dashboard must not compute business logic itself | `/stats/overview` (the route: how many each check stopped), `/stats/timeline`, `/stats/spend`, `/teams`, `/redaction-entities` | Tests with one request of every kind | `ae68574` |
| 4 | **The dashboard itself** | Faculty demo and real admin use | Next.js 16. The browser never sees the token: the dashboard's own server keeps it in an httpOnly cookie (page scripts can't read it) and forwards calls to the gateway. Six screens: overview with the **route map**, review queue, audit log, threats, cost, personal data | Screenshots on live data; 45 unit tests | `6af74a2` |
| 5 | **Tests, Docker, CI** | The plan's test list, and "works against the real stack" | Vitest + Testing Library with a mocked gateway; 16 Playwright tests against `docker compose up`; Dockerfile; CI now builds and tests the dashboard and runs the Postgres tests too | 45/45, 16/16, 392/392 | `4291bab` |
| 6 | **Bugs found by testing it for real** | Several only appeared live | No login worked inside Docker (the origin check compared against the server's own `0.0.0.0` address); "recently decided" showed the *oldest* verdicts; a "saved" message vanished; grey text failed contrast; the PII screen described a feature (swapping tokens back) the gateway doesn't have | Each fix has a test that fails without it | `4291bab` |
| 7 | **Live tamper demo in the dashboard** | The best demo moment, with the dashboard catching it, not a script | `tamper_demo --postgres --hold` edits an entry and waits; the dashboard's "Check integrity" says "Tampered: entry #2 ... its contents were changed"; Enter restores it | Done live: tampered, caught, restored, intact again | `4291bab` |

**The route map** (the overview's centrepiece):
- All of the window's requests are drawn as one band. At each check
  (intake, session, budget, screening, provider, reply check) the requests it
  stopped peel off downward in the colour of what happened to them.
- So the band visibly narrows wherever the gateway is doing work, and what's
  left at the end is what got answered.
- On a phone it becomes a simple list.

**Honest limits:**
- A changed password doesn't end sessions that are already open (L8-1).
- Every admin can do everything (L8-2).
- The lockout can be abused to lock out a known admin for 15 minutes (L8-3).
- The automated review test intercepts responses instead of deciding real
  items, because real verdicts train the defense (L8-6). The real flow was
  done by hand.

**Viva lines:**
- *Why doesn't the browser hold the token?* So a script injected into the
  page can't steal the session. The cookie is httpOnly and SameSite=Strict,
  and writes are also checked for the same origin.
- *Why compute stats in the gateway?* One source of truth, and the
  dashboard stays a thin client, as the plan requires.
- *How do you know the dashboard works?* 45 component tests, 16 browser
  tests against the real Docker stack, and both demo flows done live.

### Module 9 — Testing strategy — 2026-10-14

**Goal:** each module already tested its own part. Module 9 tests what falls
*between* them: does the gateway still work, and still keep its security
rules, once every piece is wired together? Chinmay asked for it to be done
honestly, so every new test was also run against the old code to prove it
catches what it claims to.

**What was built, why, and how:**

| # | What | Why | How | Proof | Commit |
|---|---|---|---|---|---|
| 1 | **Full-journey tests** (`test_full_pipeline.py`) | Every other test fakes the classifier and freezes the session agent; nothing checked all modules together | One request through every *real* stage - trained model, Presidio, bandit, session agent, Redis budgets, audit chain - with only the AI provider mocked. Seven tests: benign, attack, PII, over budget, fail-closed, fail-open, attack inside a tool call. Each runs twice: SQLite + fake Redis, and real Postgres + Redis | 14/14 pass | `04ccd4d` |
| 2 | **Security-rule tests** (`test_security_boundaries.py`) | The rules "no raw PII anywhere" and "keys never exposed" must hold whichever module wrote the data | Plant an email, phone, card, SSN and fake keys; send every kind of request; then search every table, every Redis key, every log line at DEBUG, every chat and admin response (admin endpoints read from the OpenAPI schema, so new ones are included automatically) and what went upstream | 8/8 pass | `04ccd4d` |
| 3 | **Fix: personal data in the logs** | Test 2 found Presidio's own logger writing the analysed text at DEBUG (and at ERROR for IBANs). `LOG_LEVEL=DEBUG` would have put raw PII in the gateway's logs | Presidio's loggers are silenced; its failures still arrive as exceptions, already wrapped without text | Test fails on the old code, passes now | `04ccd4d` |
| 4 | **Fix: provider error text reached clients** | Test 2 planted a key in a provider error and it came back in the 502 reply. The same path could reveal internal addresses (the Ollama URL) | Clients now get the gateway's own short description: `provider returned HTTP 401`, `provider timed out`, `provider unreachable (ConnectError)` | Test fails on the old code, passes now | `04ccd4d` |
| 5 | **Fix: tool calls skipped every check** | A probe put an email in nine different places in a request. Text inside an assistant's tool-call arguments reached the provider unredacted, unscored and unscanned | Redaction, threat scoring, the reply scan and the bandit's cut-and-allow step now all read tool-call arguments | Probe re-run: redacted. New tests fail on the old code | `04ccd4d` |
| 6 | **The first version of fix 5 was wrong** | Testing it with the real model showed harmless tool-call JSON scores as an attack: `{"query": "onboarding guide..."}` 0.979, while the value alone scores 0.031. It would have blocked most tool-using apps | The classifier now scores only the text values inside the JSON. Arguments are never cut (that would break their JSON), but if they still look like an attack the request is blocked | Real-model test with a harmless control: the control passes, the attack is refused | `04ccd4d` |
| 7 | **Coverage report** | Plan §4: measure it and review it once | `pytest --cov` with branch coverage: 97% of `app/`. The gaps that mattered were then tested: failures *after* the provider answered (the unchecked reply must not be returned), startup/shutdown, an old-feature-layout guard, Ollama errors | `chat.py`, `main.py`, `messages.py` now 100% | `04ccd4d` |
| 8 | **CI** | Plan §5 | Every push: Postgres + Redis services so the new tests run on both backends, coverage printed, every skip listed with its reason. New "Full checks" workflow (push to main, weekly, on demand): downloads the model from the private Hugging Face backup, runs the real-model tests (fails if any skip), the classifier and bandit evaluations, and the 16 browser tests against a freshly built Docker stack | Evaluation commands run locally: classifier macro-F1 0.908 and 3.1% false alarms, matching the shipped result | `04ccd4d` |

**Honest findings and limits:**
- Five request fields are still passed through unchecked: a message's
  `name`, `user`, tool *definitions*, `response_format` schemas and unknown
  fields (L9-1). A probe confirmed it.
- Code-like tool arguments (SQL) still score as attacks, 0.976 (L9-2), the
  same weakness as L5-2.
- L5-2 reproduces with the shipped model in a fresh process: "hello" 0.805,
  "No results." 0.903. One new test first passed *because* of this (a
  two-word tool reply scored as an attack on its own) and was rebuilt with a
  harmless control.
- The "Full checks" workflow needs a Hugging Face read token as the GitHub
  secret `HF_TOKEN`; without it, it fails loudly instead of skipping (L9-3).
- Not tested, on purpose: load testing (L9-4), the red-team stretch goal that
  wasn't built (L9-5), multi-server failover (L9-6), a real paid provider
  (L9-7).

**Viva lines:**
- *How do you know it's secure, not just tested?* The security tests don't
  check one module's output; they search everything the gateway wrote for
  planted values, including logs at DEBUG. They found two real leaks that
  every per-module test had missed.
- *How do you know your tests work?* Each new test was run against the old
  code first and failed there. One test that passed for the wrong reason was
  caught that way and rebuilt.
- *What's your coverage?* 97% of lines and branches, reviewed file by file.
  But coverage only says what ran, which is why the tests were also checked
  against broken code.

### Module 10 — Deployment — 2026-10-14

**Goal:** a demo that starts with one command, fills itself with realistic
data, can be reset to a clean state before the presentation, and runs the
same way on a machine that has never seen the project.

**What was built, why, and how:**

| # | What | Why | How | Proof | Commit |
|---|---|---|---|---|---|
| 1 | **Self-starting stack** | Before, starting meant `up`, then `alembic upgrade`, then a seed script, then creating an admin - easy to get wrong at 2 am | Compose runs one-off jobs in order: `model` (is the classifier there?), `migrate` (database setup), then the gateway (with a health check), then the dashboard and the demo traffic | A fresh clone came up and seeded itself in 81-90 s | `8dbcdbc` |
| 2 | **A restricted database login for the gateway (L7-6)** | The gateway used the database superuser, so anyone with its password could switch off the audit log's protection | `migrate` (the owner) creates `gateway_app`: may read/write the app tables, may only *add* audit entries, owns nothing. The owner password lives only in the one-off job | Tests: 8 dangerous commands refused as `gateway_app`; a full request + review + admin round trip still works. Live: the tamper trick from inside the gateway fails with *permission denied* | `8dbcdbc` |
| 3 | **Demo data** (`seed_demo.py`) | An empty dashboard demos nothing | Four teams (Acme Support, Research Lab with a tiny budget, Legal Ops with tokenizing, Red Team Sandbox for attacks), keys, policies, an admin, then **real requests through the gateway** - nothing is written into the audit log directly. Keys are derived from a secret in `.env`, never stored | Seeded twice: no duplicates. Review queue opens with 2 genuine borderline items | `8dbcdbc`, `451e8d1` |
| 4 | **Reset script** (`reset_demo.ps1` / `.sh`) | A clean slate before the presentation, and the "copy `.env.example`" step done right | Creates or completes `.env` with generated secrets (never overwriting existing values), asks before wiping, rebuilds, waits for the seed, prints the login | Run from no `.env` twice | `8dbcdbc` |
| 5 | **Demo helper + `docs/DEMO_SCRIPT.md`** | Typing curl with quotes on Windows during a live demo is how demos fail | `docker compose exec gateway python -m scripts.demo pii` (benign, pii, attack, budget, keys): each prints the reply and the audit entry. The PII step searches every table for the raw values on screen | Full dry runs in the documented order; dashboard paths checked against screenshots | `2357325` |
| 6 | **402 / 429** | A spent budget and a rate limit were both "422 blocked", like an attack | 402 Payment Required for a budget (retrying won't help), 429 for a rate limit (OpenAI's SDKs back off and retry on it) | Tests for both | `8dbcdbc` |
| 7 | **A pretend price for the free local model** | With only Ollama, nothing costs money, so the budget step could never run out | Optional setting, 0 by default; the reset script sets 60 per million tokens; the demo script says it's pretend | Budget runs out after 4 answers: 402 | `8dbcdbc` |

**What the clean-clone test caught** (a fresh copy from git in a temporary
folder, like a faculty laptop):
- the four services built the same image name in parallel and collided;
- without the model, the start failed with a bare "didn't complete", not the
  reason (now the jobs' messages are printed);
- the generated admin password was only shown at the very end, so a failed
  first start lost it;
- the bash script would have had Windows line endings on a Windows checkout;
- the "unknown model" demo request said "hello there", which the classifier
  blocked as an attack first (L5-2) - so it never showed what it was for.

Also done live for the first time: the dashboard's **Unlock key** button
(module 8 had only tested it automatically).

**Honest limits:**
- A machine without the model needs the folder copied or a Hugging Face
  token (L10-1).
- The Postgres owner password is the default, and Redis has none - both
  only listen on the laptop itself now (L10-2, L10-3).
- The demo's spend is pretend money (L10-4).
- No Kubernetes, TLS or secret manager - documented as future work (L10-5).

**Viva lines:**
- *Why a separate database user?* The hash chain *detects* tampering; the
  restricted role *prevents* the easy kind. The gateway can add audit
  entries but can't change or delete them, or switch the protection off -
  even if someone takes over the gateway process.
- *Is the demo data fake?* The teams and budgets are demo settings, but
  every audit entry, review item and refusal is a real decision by the
  real pipeline - the seed sends requests through the gateway like any app.
- *How would this scale to production?* The stateless gateway scales
  horizontally behind a load balancer (the audit writer already serialises
  across processes with an advisory lock); add TLS, a secret manager,
  passwords on Postgres and Redis, and Kubernetes for orchestration.

## 5. Lessons that cut across modules

1. **Verify live, not just with tests.** Running the real Docker stack caught
   bugs unit tests never could: the `localhost` mix-up, the SQLAlchemy version
   that broke the image, the torch/CPU crash.
2. **Attack your own system.** The biggest fixes (list-form bypass, padding
   bypass, secret leak at startup, PII in crash logs) came from deliberately
   trying to break it.
3. **Fail-closed.** A broken security check must not become an open door.
4. **PII is a hard boundary.** Modules 4, 5, 6a and 6b each have tests and live
   checks proving raw PII is not in logs, the database, or Redis.
5. **Check your test set for leaks.** 33/91 test attacks were near-copies of
   training data; the real score was lower than reported.
6. **Decide pass/fail before seeing results**, and stop instead of re-running
   on the same test set until something passes.
7. **Report honestly.** "The bandit ties a threshold" and "the DQN is NO-GO" are
   real findings, with the reason and the evidence.
8. **Measure before blaming.** When the Postgres load test stalled, Postgres
   turned out to be idle (`ClientRead`), an A/B showed the audit log cost
   nothing, and a profile named the real cause (a module 2 HTTPS client per
   request). Each step ruled one thing out before the next guess.
9. **A test must fail on broken code.** Module 9 ran every new test against
   the old code first. One passed anyway (a short harmless reply scored as an
   attack on its own), so it proved nothing until it got a control case.

## 6. Interview / viva cheat sheet

- **Why isn't the bandit RL?** A bandit's action doesn't change the next
  situation; each request is independent. 6b's actions (lockout, challenge)
  change the rest of the session, so it needs RL (states, delayed reward).
- **Why is the DQN not the default?** It failed a criterion set before training,
  twice. Run 2 was safe and better on average, but not provably better for
  every seed at low attack rates. `auto` will switch to it only on a GO verdict.
- **Why fail-closed?** A failed check that lets traffic through is a bypass an
  attacker can trigger. Availability cost is accepted and documented (L6a-24).
- **How do you know there's no data leakage?** Near-duplicate clustering
  (word 8-grams, union-find), whole clusters per split, independently
  re-checked: 0 clusters span train and test.
- **Why does the bandit only tie a threshold?** The classifier's scores are
  bimodal; a missed attack scores ~0, and no policy on the score can catch it.
  The bandit's value shows under drift.
- **Why did you ship a classifier that failed your own criterion?** It failed
  one of three: a 194-row old benchmark, by 6 attacks. On a 5× larger locked
  test the old model flags 27.5% of benign prompts. We recorded it as an
  override with reasons rather than quietly changing the rule.
- **What makes the audit log tamper-evident and not just read-only?** Each
  entry's hash covers its contents and the previous entry's hash. The
  trigger stops normal users; a superuser can disable it, but can't make
  `verify` pass after an edit without rewriting every later hash, and the
  head hash can be recorded outside the database.
- **What can't the hash chain detect?** Deleting the newest entries: the rest
  is still a valid chain. That's why `verify` returns `entry_count` and
  `head_hash` (L7-2).
- **Doesn't logging slow every request down?** No: the request only queues the
  entry. Measured A/B on Postgres: no meaningful difference.
- **How did you test the whole system, not just the parts?** Seven
  full-journey tests run one request through every real stage, on SQLite
  and on real Postgres + Redis, and four security tests search every table,
  Redis key, log line and response for planted PII and keys. They found two
  leaks and a whole request field (tool calls) that skipped every check.
- **What happens if your laptop dies before the demo?** Any machine with
  Docker: clone, copy the model folder (or set a Hugging Face token), run
  the reset script. Tested from a fresh clone: up and seeded in ~1.5 min.
- **What would you improve?** Re-fit the bandit's bands to calibrated
  scores, a larger validation set for the RL lockout constraint, admin roles and session revocation (L8-1, L8-2), real session logs to replace the
  simulator (L6b-3).

## 7. What's next

1. Add the `HF_TOKEN` secret, then push modules 9 and 10 (L9-3).
2. Rehearse `docs/DEMO_SCRIPT.md` twice on the presenting laptop.
3. Module 11 is a reference roadmap: nothing to build.
4. (Optional) Pre-registered re-fit of 6a's band edges to v2's scores (L6a-30).

---

## Changelog of this document

- 2026-10-13: first version, written from the records for modules 1-6b and the
  start of the data expansion.
- 2026-10-13 (later): data expansion section updated with the v2 result and the
  v3 attempt.
- 2026-10-13 (end of day): v3 result, v2 override, 6a re-check, RL v3 NO-GO.
- 2026-10-13 (night): module 7, tamper-evident audit logging.
- 2026-10-14: module 7 review pass (L2-2 fixed, three smaller bugs, one test gap).
- 2026-10-14 (later): optional Ollama provider and the first real end-to-end run.
- 2026-10-14 (evening): streaming rejected up front (L2-3).
- 2026-10-14 (night): module 8, admin dashboard.
- 2026-10-14 (later): module 9 section, lesson 9, a testing viva answer; "What's next" updated.
- 2026-10-14 (later still): module 10 section, a deployment viva answer; "What's next" updated.
- 2026-10-15: IEEE paper material collected in `docs/IEEE_PAPER_MATERIAL.md` (section-by-section content, result tables, honest claims/non-claims).
- 2026-10-15 (later): 6-page IEEE conference paper written in `paper/ieee_paper.tex` (IEEEtran, TikZ/pgfplots figures), compiled to `paper/ieee_paper.pdf`.
- 2026-10-15 (evening): narrated video walkthrough script in `docs/VIDEO_DEMO_SCRIPT.md` (11 scenes, ~13 min, built on `DEMO_SCRIPT.md`).
