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

Last updated: 2026-10-07

---

## Open

### Module 5: Threat detection classifier

| ID | Limitation | Impact | Why it exists | Future fix | Unblocked by | Status |
|---|---|---|---|---|---|---|
| L5-1 | Prompt-injection detection only just meets its target: F1 0.86 vs 0.85, measured on 29 test examples (one miss ≈ 3.5 recall points) | ~1 in 6 injections missed; the metric itself is noisy | Public injection data is small (~200 training rows) | Add more labelled injection data (e.g. more public sets, our own red-team prompts) and retrain; re-evaluate on a larger test set | More labelled injection data; ~40 min GPU retrain (`training/train_classifier.py`) | Open |
| L5-2 | False positives on ordinary imperative phrasing: "Forget about the budget numbers, focus on the timeline" scores 0.98 injection | Normal requests can look like attacks | Learned from the training data; the class weighting added for L5-1 makes it slightly more likely | Add hard-negative benign examples ("ignore the typo…", "forget X, focus on Y") to training; calibrate scores (temperature scaling) | A hard-negative benign dataset; module 6a thresholds in place to measure the effect | Open (module 6a must allow for it) |
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
