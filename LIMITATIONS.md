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

Last updated: 2026-10-07 (module 6a added)

---

## Open

### Module 6a: Adaptive defense, tactical bandit

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L6a-1 | On benchmark-like traffic the bandit only ties a tuned static threshold (0.720 vs 0.719 mean reward, i.i.d. held-out data), and no policy catches the ~4% of attacks the classifier scores near 0 | The policy layer adds adaptivity, not detection accuracy | The classifier's scores are bimodal (168/190 attacks ≥ 0.999, 195/200 benign < 0.01; also true on unseen Gandalf/Alpaca data), so there's almost nothing in between for a policy to learn | Improve the detector (L5-1); calibrate scores (temperature scaling) so mid-range scores carry information | A better or calibrated classifier | Open |
| L6a-2 | Learning is slow at the default 2% spot-check rate: under simulated false-positive drift the gain over a static threshold is +0.014 reward per request (vs +0.137 with every decision labelled) | Drift takes many requests to correct; benign refusals stay high meanwhile (19% vs 21%) | Labels only come from human review: escalations plus a 2% sample | Raise `BANDIT_SPOT_CHECK_RATE` during suspected drift (10% gives +0.100, benign refusals 6.6%); add cheaper label sources (user "this was wrongly blocked" reports) | Reviewer capacity; module 8's review UI to make reviewing cheap | Open |
| L6a-3 | LinUCB is linear, so feedback generalises across the whole feature space: one-sided labels in one score region also shift decisions elsewhere (e.g. 40 "attack" labels at p=0.15 make it redact clearly benign p≈0 traffic) | Unbalanced feedback can over-tighten (or over-relax) unrelated traffic | A linear reward model per arm is the standard, explainable LinUCB choice | Spot checks on allowed traffic counterbalance it (tested); longer term, binned/one-hot score features or a non-linear bandit (e.g. neural-linear) | Enough real feedback to justify a richer model | Open (documented by `test_feedback_in_one_region_needs_counter_evidence_elsewhere`) |
| L6a-4 | The review-queue decide endpoint has no authentication | Anyone who can reach the gateway can submit forged verdicts and train the bandit on false labels | All `/v1/admin/*` routes lack auth until module 8 (same root cause as L3-1) | Admin auth on every admin route; record the authenticated reviewer instead of a free-text name | Module 8 | Planned (module 8) |
| L6a-5 | Review excerpts store up to 4,000 characters of post-redaction prompt text, with no retention limit | PII that Presidio misses, and non-PII confidential text, are kept in `review_queue_items` | Reviewers need text to judge; it's the same text that already went (or would have gone) upstream | Retention policy plus purge job; drop the excerpt once an item is reviewed | A retention decision (same as L4-1); a scheduler | Open |
| L6a-6 | `redact_and_allow` cuts whole ~158-token windows: on a short prompt it removes the whole message (in effect a block that still costs a provider call), and on long ones it also cuts benign text near the attack | Degraded answers; wasted provider calls on short prompts | The classifier scores windows, not tokens | Token-level attribution (e.g. attention or gradient saliency) to cut only the attack span | Time to build and evaluate span attribution | Open |
| L6a-7 | An escalated request stays blocked even if a reviewer clears it; the client must resend | Benign escalations cost the user a retry | The gateway is a synchronous proxy, with no hold-and-release flow | An async hold queue with client polling or a callback, replaying the request on a benign verdict | A product decision on async semantics | Open |
| L6a-8 | Rewards are a hand-authored proxy table (reward.py), not measured costs, and every offline result depends on it | Different real costs would shift the action bands and the comparisons | No cost data exists for a capstone deployment | Fit the weights to measured outcomes (incident cost, support tickets from false blocks) | Real deployment data | Open |
| L6a-9 | The `escalation_bias` hook is read but never set: nothing assigns `ctx.metadata["session_id"]` yet, so every request gets the neutral 0.0 | Session-level tightening isn't active | Sessions and the bias writer are module 6b's job | Module 6b derives session IDs and writes the bias | Module 6b | Planned (module 6b) |

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
| — | (none yet; fixed bugs are recorded in PROGRESS.md, not here) | | |
