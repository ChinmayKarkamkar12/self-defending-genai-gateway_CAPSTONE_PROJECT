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
          └─ defense_feedback  leaks become a learning signal for 6a        [module 6a]
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
| 2026-10-13 | Classifier v2 training (in progress) | — |

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

### Data expansion (v2) — in progress since 2026-10-12

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

---

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
- **What would you improve?** More and better data (now in progress), score
  calibration, admin auth (module 8), real session logs to replace the
  simulator (L6b-3).

## 7. What's next

1. Finish the data expansion: classifier v2 decision, re-check 6a, RL v3.
2. Module 7: audit logging (tamper-evident).
3. Module 8: admin dashboard (Next.js) and admin authentication.
4. Module 9: testing strategy; Module 10: deployment.

---

## Changelog of this document

- 2026-10-13: first version, written from the records for modules 1-6b and the
  start of the data expansion.
- 2026-10-13 (later): data expansion section updated with the v2 result and the
  v3 attempt.
