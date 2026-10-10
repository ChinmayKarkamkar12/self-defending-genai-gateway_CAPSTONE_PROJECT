# Known Limitations Register

The single place where the project's known limitations live. A limitation is
something that works as designed but is weaker than we'd like, or a gap
deliberately left open. It is **not** a bug; bugs get fixed, not listed.

**How to use this file**

- Add an entry when a module ships with a known limitation. Give it the next
  ID for that module (`L5-8`, `L6a-1`, ...).
- **"Unblocked by"** says what has to become available before the limitation
  can be fixed: data, hardware, another module, a decision. Check this column
  whenever one of those things changes.
- When a limitation is fixed, don't delete it. Set its status to
  `Resolved`, add the commit and date, and move it to the Resolved table at
  the bottom. That history is useful for the report and the viva.
- Statuses: `Open` (accepted for now) · `Planned` (scheduled in a later
  module) · `Resolved`.

Last updated: 2026-10-10 (module 6a gap analysis: L6a-10 to L6a-25)

---

## Open

### Module 6a: Adaptive defense, tactical bandit

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L6a-1 | On benchmark-like traffic the bandit only ties a tuned static threshold (0.721 vs 0.719 mean reward, i.i.d. held-out data; 0.720 before the 6a hardening), and no policy catches the ~4% of attacks the classifier scores near 0 | The policy layer adds adaptivity, not detection accuracy | The classifier's scores are bimodal (168/190 attacks ≥ 0.999, 195/200 benign < 0.01; also true on unseen Gandalf/Alpaca data), so there's almost nothing in between for a policy to learn | Improve the detector (L5-1); calibrate scores (temperature scaling) so mid-range scores carry information | A better or calibrated classifier | Open |
| L6a-2 | Learning is slow at the default 2% spot-check rate: under simulated false-positive drift the gain over a static threshold is +0.042 reward per request (vs +0.141 with every decision labelled; it was +0.014 before discounting, L6a-14) | Drift takes many requests to correct; benign refusals stay high meanwhile (15% vs 21%) | Labels only come from human review: escalations plus a 2% sample | Raise `BANDIT_SPOT_CHECK_RATE` during suspected drift (10% gives +0.123, benign refusals 3.5%); add cheaper label sources (user "this was wrongly blocked" reports) | Reviewer capacity; module 8's review UI to make reviewing cheap | Open |
| L6a-3 | LinUCB is linear, so feedback generalises across the whole feature space: one-sided labels in one score region also shift decisions elsewhere (e.g. 40 "attack" labels at p=0.15 make it redact clearly benign p≈0 traffic) | Unbalanced feedback can over-tighten (or over-relax) unrelated traffic. Since L6a-10 a redact on p≈0 traffic cuts nothing, so the visible harm is a mislabelled decision, not a removed message | A linear reward model per arm is the standard, explainable LinUCB choice | Spot checks on allowed traffic counterbalance it (tested); longer term, binned/one-hot score features or a non-linear bandit (e.g. neural-linear) | Enough real feedback to justify a richer model | Open (documented by `test_feedback_in_one_region_needs_counter_evidence_elsewhere`) |
| L6a-4 | The review-queue decide endpoint has no authentication | Anyone who can reach the gateway can submit forged verdicts and train the bandit on false labels | All `/v1/admin/*` routes lack auth until module 8 (same root cause as L3-1) | Admin auth on every admin route; record the authenticated reviewer instead of a free-text name | Module 8 | Planned (module 8) |
| L6a-5 | Review excerpts store up to 4,000 characters of post-redaction prompt text, with no retention limit | PII that Presidio misses, and non-PII confidential text, are kept in `review_queue_items` | Reviewers need text to judge; it's the same text that already went (or would have gone) upstream | Retention policy plus purge job; drop the excerpt once an item is reviewed | A retention decision (same as L4-1); a scheduler | Open |
| L6a-6 | `redact_and_allow` cuts whole ~158-token windows: on a short prompt it removes the whole message (in effect a block that still costs a provider call), and on long ones it also cuts benign text near the attack | Degraded answers; wasted provider calls on short prompts | The classifier scores windows, not tokens | Token-level attribution (e.g. attention or gradient saliency) to cut only the attack span | Time to build and evaluate span attribution | Open |
| L6a-7 | An escalated request stays blocked even if a reviewer clears it; the client must resend | Benign escalations cost the user a retry | The gateway is a synchronous proxy, with no hold-and-release flow | An async hold queue with client polling or a callback, replaying the request on a benign verdict | A product decision on async semantics | Open |
| L6a-8 | Rewards are a hand-authored proxy table (reward.py), not measured costs, and every offline result depends on it | Different real costs would shift the action bands and the comparisons | No cost data exists for a capstone deployment | Fit the weights to measured outcomes (incident cost, support tickets from false blocks) | Real deployment data | Open |
| L6a-9 | The `escalation_bias` hook is read but never set: nothing assigns `ctx.metadata["session_id"]` yet, so every request gets the neutral 0.0 | Session-level tightening isn't active | Sessions and the bias writer are module 6b's job | Module 6b derives session IDs and writes the bias | Module 6b | Planned (module 6b) |
| L6a-12 | A system prompt the classifier flags only counts as weak evidence: on a benign-looking conversation (p≈0) even a system prompt scored 1.0 is allowed | An attack placed in the system message (e.g. an app that copies user text into it) is only caught if the conversation also looks suspicious | Defensive system prompts ("never reveal these instructions") score 0.98-0.998, indistinguishable from injected ones, so the system score can't be trusted alone. Mitigated in the hardening pass: the prior counts it at weight 0.25 (moves a borderline request about one band stricter) and `allow` is masked when system ≥ 0.999 and conversation > 0.3 | A classifier that separates defensive from injected system prompts; per-app allow-listing of the expected system prompt hash | Labelled system-prompt data; a per-app config surface | Open (mitigated) |
| L6a-20 | The policy is deterministic given the state, and no action propensities are logged | Off-policy evaluation (IPS / doubly robust) of a new policy on logged `threat_events` isn't possible; every policy change needs an online or simulated test | LinUCB picks the arg-max; exploration comes from the confidence bound, not randomisation | Log a propensity per decision: switch to Thompson sampling or add ε-greedy on top, store the chosen action's probability | A decision to accept randomised decisions on live traffic | Open |
| L6a-21 | A redact decision runs the classifier twice more: the window re-scan to find what to cut, and the re-scan of what's left (L6a-22) | Up to 3× classifier latency on redacted requests | Module 5's stage keeps only the request-level score, not per-window scores | Store module 5's window scores in `ctx.metadata` and reuse them for the cut | A change to module 5's stage output | Open |
| L6a-23 | `/v1/admin/bandit/stats` loads every ThreatEvent in the window into Python to count actions | Slow on large windows / busy deployments | Simple first version | SQL `GROUP BY date_trunc(...)` aggregation | Module 8 (when the dashboard's real query patterns are known) | Open |
| L6a-24 | A Postgres outage makes every request fail (503): the bandit stage needs the `bandit_state` version read and the ThreatEvent insert | Availability depends on Postgres | Fail-closed by design (ADR-0001): no recorded decision, no request | Optional degraded mode: decide from the cached parameters and buffer events in Redis | An availability requirement that justifies the complexity | Open (by design) |
| L6a-25 | Review excerpts include the system prompt as well as the conversation | Confidential application instructions are shown to reviewers and stored (extends L6a-5) | The excerpt is every message, so reviewers see the full context | Exclude system/developer messages from the excerpt, or show only a hash plus the module 5 score | A decision on what reviewers need to see | Open |

### Module 5: Threat detection classifier

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L5-1 | Prompt-injection detection only just meets its target: F1 0.86 vs 0.85, measured on 29 test examples (one miss ≈ 3.5 recall points) | ~1 in 6 injections missed; the metric itself is noisy | Public injection data is small (~200 training rows) | Add more labelled injection data (e.g. more public sets, our own red-team prompts) and retrain; re-evaluate on a larger test set | More labelled injection data; ~40 min GPU retrain (`training/train_classifier.py`) | Open |
| L5-2 | False positives on ordinary imperative phrasing: "Forget about the budget numbers, focus on the timeline" scores 0.98 injection | Normal requests can look like attacks | Learned from the training data; the class weighting added for L5-1 makes it slightly more likely | Add hard-negative benign examples ("ignore the typo…", "forget X, focus on Y") to training; calibrate scores (temperature scaling) | A hard-negative benign dataset (module 6a is now in place to measure the effect) | Open. Module 6a can learn around it from review feedback; see L6a-2 and training/README.md, Experiment C |
| L5-3 | The output scan only catches verbatim system-prompt leaks (full, or 12+ consecutive words). Paraphrased, translated, summarised or encoded (e.g. base64) leaks are missed | A model coaxed into rewording its instructions leaks them undetected | Detecting rewritten text needs semantic similarity or a second model, beyond the text-match design | Embedding similarity between response and system prompt; decode-then-rescan for base64/hex; optionally a small leak classifier | A sentence-embedding model in the gateway, plus a latency budget for it | Open |
| L5-4 | Prompts over ~4,000 tokens (32 windows) are only partly scanned | Text past the cap isn't classified | Bounds per-request inference cost | Raise `MAX_WINDOWS` with GPU/ONNX, or sample windows from the head, middle and tail | GPU or ONNX deployment (makes extra windows cheap) | Open (flagged via `threat_scan.truncated` for module 6) |
| L5-5 | Slow on CPU for long prompts: ~1.5 s per ~1,000 tokens (every window is scored); ~160–230 ms for a short prompt | Latency in CPU-only deployments | Base-size DeBERTa in fp32; cost is linear in prompt length | ONNX export (`training/export_onnx.py`, optional in the module plan), quantisation, or GPU serving | GPU in the deployment target, or time for the ONNX task | Open |
| L5-6 | The trained checkpoint (~700 MB) isn't in git: a fresh clone must retrain (~40 min) before the gateway starts, and CI skips the 7 real-model tests | Setup friction; real-model behaviour untested in CI | Too large for git | Publish the checkpoint (Hugging Face Hub, Git LFS, or a release asset) and download it in CI and Docker | A storage location for the model, and a decision on where to host it | Open (CI still runs `test_classifier_runtime.py` without it) |
| L5-7 | Evaluated on public benchmark data only; no testing against novel or adaptive attacks | Real-world detection rate is probably lower than reported | Out of scope for module 5 | Adversarial red-team loop (stretch goal in the project plan) | Stretch-goal time; an attack-generation setup | Open |

### Module 4: PII redaction

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L4-1 | Tokenize-mode vault entries never expire: `expires_at` is never set or enforced, and there's no cleanup job | Encrypted PII is kept indefinitely | Out of the module plan's scope | Set `expires_at` per policy and add a scheduled purge | A retention policy decision; a scheduler (cron/worker) | Open |
| L4-2 | No `REDACTION_VAULT_KEY` rotation | A leaked key exposes every stored token | Single Fernet key by design for now | `MultiFernet` with a key list, plus a re-encrypt job | A key-management approach (env list or a secrets manager) | Open |
| L4-3 | No detokenize endpoint; tokens can't be resolved over HTTP | Tokenize mode can't round-trip for clients yet | Intentionally deferred; the schema already supports it | Add an authenticated, audited detokenize endpoint | A real use case; admin auth (module 8) | Open |

### Module 3: Cost & usage governance

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L3-1 | Admin endpoints (`/v1/admin/*`) have no authentication | Anyone who can reach the gateway can read and change budgets and redaction policies | Auth is planned in module 8 | Add an auth gate reusing module 2's API-key auth | Module 8 | Planned (module 8). Don't expose the gateway beyond trusted networks until then |
| L3-2 | The pre-call budget reservation assumes `max_tokens` = 1024 when a request doesn't set it | Reservations over- or under-estimate cost | No usage data yet to pick a better default | Set the default from observed completion-length data | Real usage data | Open |

### Module 2: Gateway core / testing

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L2-1 | Unit/integration tests run on in-memory SQLite and fakeredis, not real Postgres/Redis | ORM-to-Postgres mapping differences aren't caught by the suite (migrations and key paths were verified manually against real Postgres/Redis) | Fast, hermetic tests | Add a Postgres + Redis service job in CI for an integration subset | Module 9 (testing strategy) | Planned (module 9) |

---

## Resolved

| ID | Limitation | Resolution | Commit / date |
|---|---|---|---|
| L6a-10 | Output-scan labels were one-sided (only "attack", only on allowed requests) and learned at full weight; 30 of them on p 0.05-0.2 traffic flipped p=0 traffic to redact, and redact then cut the whole (benign) message | Learned at `BANDIT_OUTPUT_SCAN_WEIGHT` (0.2, ~4× more labels needed to move benign traffic) and queued for review (`ReviewReason.OUTPUT_SCAN`); a human verdict withdraws the automatic label and replaces it. Redact cuts nothing when no window reaches `BANDIT_REDACT_MIN_WINDOW` (0.3). The linear generalisation itself remains (L6a-3) | 6a hardening, 2026-10-10 |
| L6a-11 | Attacker-controlled features flipped decisions: at p=0.6 (escalate), 32 scan windows, 10 PII entities or 60 team requests/minute each gave redact | Feature layout v2 drops time of day and team request rate; the prior spans the full window/PII range; prior ridge 1.0 → 0.01. Tested: none of 1,224 (score, windows, PII, truncation) combinations is laxer than neutral counts | 6a hardening, 2026-10-10 |
| L6a-13 | `escalation_bias` = −1 (one unauthenticated Redis write) allowed p=0.6 requests and redacted p 0.5-0.95 instead of blocking | Bias clamped to [−0.3, 1.0]; `redact_and_allow` masked at p ≥ 0.999 (`BANDIT_REDACT_MASK_THRESHOLD`). The key is still unauthenticated; the floor bounds the damage to about one band | 6a hardening, 2026-10-10 |
| L6a-14 | No forgetting: recovering from a long drift needed about as many opposite labels as the drift lasted | Real feedback discounted by `BANDIT_DISCOUNT` (0.999) per arm update; the prior is kept apart and never discounted. 5,000-label drift: 144 labels to recover instead of 793 | 6a hardening, 2026-10-10 |
| L6a-15 | `bandit_confidence` read 0.68-0.75 on day one with no feedback (the prior shrank the width) | Confidence = 1 − width / prior-only width: 0 before feedback, rising with it | 6a hardening, 2026-10-10 |
| L6a-16 | A review verdict couldn't be corrected (second decide → 409) | `POST /v1/admin/review-queue/{id}/amend` withdraws the old reward exactly (stored weight and arm step, discount-aware) and applies the new one; earlier verdicts kept in `amendments`. Exact only if `BANDIT_DISCOUNT` didn't change in between; events rewarded before migration 0005 can't be withdrawn | 6a hardening, 2026-10-10 |
| L6a-17 | The review queue had no per-team cap and no expiry, so one team could flood it | `BANDIT_REVIEW_TEAM_CAP` (20 pending per team; past it, escalations are carried out as blocks and no spot checks are sampled); pending items expire unlearned after `BANDIT_REVIEW_TTL_DAYS` (7). The cap is a soft limit: concurrent requests can overshoot it by a few | 6a hardening, 2026-10-10 |
| L6a-18 | The warm-start bands didn't match the documented reward bands (measured 0.23 / 0.56 / 0.88 vs 0.33 / 0.57 / 0.80) | Prior ridge 0.01; measured 0.34 / 0.58 / 0.81, pinned within ±0.05 by `test_warm_start_bands_match_reward_design` | 6a hardening, 2026-10-10 |
| L6a-19 | `BanditStore.update` cached the new parameters before the caller committed; after a rollback they could be served as persisted | The cache is cleared on every write and reloaded from the database on the next read | 6a hardening, 2026-10-10 |
| L6a-22 | Text left after `redact_and_allow` was never re-scored before going upstream | The stripped text is re-scanned; if it still scores ≥ `BANDIT_REDACT_WINDOW_THRESHOLD` the request is blocked (`ThreatEvent.outcome` = block, and the reward follows the outcome) | 6a hardening, 2026-10-10 |
