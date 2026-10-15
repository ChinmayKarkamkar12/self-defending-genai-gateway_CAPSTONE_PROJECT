# IEEE Paper Material — Self-Defending GenAI Gateway

Everything needed to write the IEEE paper, arranged in IEEE section order.
Every number comes from the project's own records (`training/README.md`,
`LIMITATIONS.md`, `PROGRESS.md`, `docs/PROJECT_JOURNEY.md`, the code), so it
can be checked. Nothing here is rounded up or made to look better than it is.

Written 2026-10-15. Team: Chinmay Karkamkar (ENG23DS0007), Aditya S
(ENG23DS0001), Priyanka M (ENG23DS0026). Guide: Mr. Monish L.

---

## 0. Read this first: what the paper can and cannot honestly claim

**The paper's real strength** is not "we beat the state of the art at
detecting prompt injection". It's three things:

1. A **complete, working system** that combines five defences in one
   fail-closed pipeline (cost, PII, detection, adaptive policy, audit), tested
   end to end.
2. A **hybrid adaptive defence**: a contextual bandit for per-request
   decisions and a reinforcement-learning agent for per-session decisions,
   with a clear argument for why each problem needs a different technique.
3. **Rigorous, honest evaluation**: leak-free data splits, pass/fail criteria
   written *before* training, a locked test set, and negative results
   reported with their causes.

**Claim these (all supported by evidence):**

| Claim | Evidence |
|---|---|
| The classifier (v2) reaches macro-F1 0.908, injection F1 0.949, 3.1% benign false positives on a 950-row locked test | training/README.md, "Classifier v2 result" |
| A 5x larger test showed the first classifier's 0.933 macro-F1 did not generalise (0.490 on the new test) | same |
| The bandit matches a tuned threshold on i.i.d. data and beats it under false-positive drift (+0.141 reward/request with full feedback, benign refusals 21.0% → 0.9%) | training/README.md, 6a Experiments A and C |
| The RL agent cuts attack-session breaches versus a rule (8.3% vs 11.7%) but fails the safety criterion on benign lockouts, so the rule stays the default | training/README.md, "Session agent v3 result" |
| The audit log detects tampering, even by a database superuser | tamper demo, ADR-0002, module 7 tests |
| No raw PII is stored or logged anywhere (tested by searching every table, Redis key, log line and response) | `test_security_boundaries.py`, module 9 |

**Do NOT claim these (reviewers or examiners will catch them):**

- ❌ "RL outperforms rule-based defence." It was NO-GO three times.
- ❌ "The bandit improves detection accuracy." It ties a tuned threshold on
  normal data, and with v2 and realistic feedback it is slightly *worse* at
  low attack rates (−0.020 to −0.024, L6a-30).
- ❌ "Robust against adaptive attackers." Never tested (L9-5, L5-7).
- ❌ "Production-ready / scalable." ~9 requests/s on a laptop, single node,
  no TLS, no load test (L9-4, L10-5).
- ❌ "Evaluated on real-world traffic." Classifier: public benchmarks. Bandit:
  held-out data plus a simulated drift. RL: a simulator with real prompts but
  synthetic session structure (L6b-3).
- ❌ Comparison with Llama Guard, Lakera Guard, NeMo Guardrails etc. was
  **not done**. Don't imply it was. (See §15 for how to add it.)

---

## 1. Title options

1. **A Self-Defending Gateway for Enterprise LLM Access: Hybrid Bandit–RL
   Adaptive Defence with Tamper-Evident Auditing** (recommended)
2. Securing Enterprise LLM Traffic with a Fail-Closed Gateway: PII Redaction,
   Injection Detection and Adaptive Response
3. Per-Request Bandits and Per-Session Reinforcement Learning for Prompt-
   Injection Defence in an LLM Gateway

## 2. Index Terms (keywords)

Large language models, prompt injection, jailbreak detection, PII redaction,
contextual bandits, deep Q-network, reinforcement learning, tamper-evident
logging, LLM security gateway.

---

## 3. Abstract (draft, ~230 words — edit freely)

> Enterprises adopting large language models (LLMs) face three risks at once:
> sensitive personal data sent to external providers, prompt-injection and
> jailbreak attacks, and uncontrolled cost. We present a self-defending
> gateway: a reverse proxy that applications reach by changing only their SDK
> base URL. Every request passes a fail-closed pipeline that enforces budgets
> atomically, redacts personally identifiable information (PII) with
> Microsoft Presidio and format-checked patterns, and scores the prompt with a
> fine-tuned DeBERTa-v3 classifier using overlapping windows. Detection is
> separated from response: a LinUCB contextual bandit chooses per request
> among allow, redact, block and escalate-to-human, learning from reviewer
> verdicts, while a deep Q-network (DQN) agent acts on whole sessions, with
> actions that tighten, challenge or lock out a persistent attacker. Every
> decision is recorded in a SHA-256 hash-chained, append-only audit log. On a
> locked 950-prompt test set, the classifier reaches macro-F1 0.908 with a
> 3.1% benign false-positive rate. The same test showed that an earlier
> model's 0.933 on a smaller benchmark did not generalise (0.490). The bandit
> matches a tuned threshold on i.i.d. data and, under simulated false-positive
> drift, gains 0.141 reward per request while cutting benign refusals from
> 21.0% to 0.9%. The DQN reduces session breaches against a rule-based policy
> (8.3% vs 11.7%) but exceeds a pre-registered benign-lockout limit, so the
> rule remains the default. We report these negative results and their
> causes as part of the contribution.

---

## 4. Introduction — content to write

**Paragraph 1 — context.** Companies route employee and customer requests to
hosted LLMs (OpenAI, Anthropic). The application sends the prompt directly to
the provider; nothing sits in between.

**Paragraph 2 — the three risks.**
- *Data leakage:* users paste emails, phone numbers, card numbers, API keys.
- *Attacks:* prompt injection ("ignore previous instructions…") and
  jailbreaks (role-play templates such as DAN) try to override the
  application's instructions or extract its system prompt. Listed as LLM01 in
  the OWASP Top 10 for LLM Applications.
- *Cost:* token-based billing with no per-team limits.

**Paragraph 3 — the gap.** Existing tools usually solve one of these in
isolation (a PII library, a guard classifier, an API gateway with rate
limits), and guard classifiers use a fixed threshold that can't adapt when
the classifier's errors drift. They also judge each request alone, so an
attacker who keeps rephrasing is never treated differently from a first-time
user.

**Paragraph 4 — our approach** (one-sentence overview of the gateway).

**Paragraph 5 — contributions (put this as a bulleted list; reviewers read
it first):**

1. A drop-in, fail-closed LLM gateway that combines atomic budget control,
   PII redaction, windowed injection/jailbreak detection, adaptive response
   and tamper-evident auditing in one pipeline, with no raw PII stored
   anywhere.
2. A two-tier adaptive defence that separates *detection* from *response*: a
   LinUCB contextual bandit for independent per-request decisions, and a DQN
   agent for sequential per-session decisions, with session-level actions
   (challenge, lockout) that act on attacks the classifier misses.
3. A pre-registered evaluation protocol (leak-free near-duplicate-aware
   splits, a hash-locked test set, criteria fixed before training) and its
   results, including two negative findings: an earlier classifier's score
   did not generalise, and the RL agent did not pass its safety criterion.
4. A hash-chained audit log with three layers of protection (application
   guard, database trigger, restricted database role) that detects
   tampering even by a database superuser.

**Last line:** "Section II reviews related work, Section III describes the
system, …, Section VIII concludes."

---

## 5. Related Work — what to cover

Each group: 1–2 sentences per work, then one sentence on how we differ.
**Verify every citation yourselves before using it** (title, authors, year,
venue). These are well-known works in each area; do not cite anything you
haven't opened.

| Area | Works to look up and cite | How we differ |
|---|---|---|
| Prompt injection attacks | Perez & Ribeiro, "Ignore Previous Prompt" (2022); Greshake et al., indirect prompt injection (2023); Liu et al., prompt injection against LLM-integrated applications (2023); OWASP Top 10 for LLM Applications | We defend at a proxy, not inside the model |
| Jailbreaks | Wei et al., "Jailbroken: How Does LLM Safety Training Fail?" (2023); Shen et al., "Do Anything Now" in-the-wild jailbreaks (2023) — this is the source of one of our datasets (TrustAIRLab) | We detect and respond, and we measure over-defence too (NotInject) |
| Guard models / guardrails | Llama Guard (Inan et al., 2023); NeMo Guardrails (Rebedea et al., 2023); ProtectAI / Lakera-style injection classifiers | They output a label with a fixed threshold; we add an adaptive policy layer and session memory |
| Classifier backbone | DeBERTa / DeBERTaV3 (He et al., 2021) | — |
| PII detection | Microsoft Presidio (tool); spaCy NER | We combine it with format-validated patterns (Luhn) and a strict no-raw-PII storage rule |
| Contextual bandits | LinUCB (Li et al., WWW 2010); discounted/non-stationary bandits (e.g. Garivier & Moulines, 2011) | Applied to security response with a safety mask and a warm-start prior |
| Deep RL | DQN (Mnih et al., Nature 2015); reward shaping (Ng, Harada & Russell, ICML 1999); Stable-Baselines3 (Raffin et al., JMLR 2021) | Applied at session level, gated by a pre-registered go/no-go against a rule |
| RL in cyber-defence | Surveys of RL for intrusion detection / cyber defence (e.g. Nguyen & Reddi) | Ours is evaluated against a strong rule baseline and reported as NO-GO |
| Tamper-evident logs | Schneier & Kelsey, secure audit logs (1999); Crosby & Wallach, tamper-evident logging (USENIX Security 2009) | Hash chain plus DB trigger plus least-privilege role |
| Evaluation hygiene | Data leakage / near-duplicate contamination literature; pre-registration practice | We found and removed 33/91 leaked test attacks |

---

## 6. System Architecture (Section III)

### 6.1 Deployment view (Figure 1)

```
 Enterprise app (OpenAI/Anthropic SDK, base_url → gateway)
        │  API key
        ▼
 ┌───────────────────── Gateway (FastAPI) ─────────────────────┐
 │  pipeline of stages (fixed order, each ALLOW / MODIFY / BLOCK)│
 └──────┬──────────────────┬──────────────────┬────────────────┘
        │                  │                  │
   PostgreSQL           Redis            LLM provider
 (teams, keys, audit,  (budgets, rate    (OpenAI / Anthropic /
  bandit state,         limits, session    optional local Ollama)
  review queue)         state, admin
                        sessions)
        ▲
 Admin dashboard (Next.js) — reads the gateway's admin API only
```

Use `diagram.png` from the repo root as a starting point, redrawn cleanly.

### 6.2 Request pipeline (Figure 2)

| Order | Stage | What it does | Module |
|---|---|---|---|
| 0 | auth | API key looked up by its SHA-256 hash | 2 |
| 1 | session_guard | is the key locked out? assign the session | 6b |
| 2 | budget_check | atomic Redis reservation of estimated cost; token-bucket rate limit | 3 |
| 3 | threat_detection | DeBERTa scores every message (windowed) | 5 |
| 4 | pii_redaction | Presidio + regex; mask or tokenize | 4 |
| 5 | bandit_policy | allow / redact / block / escalate | 6a |
| 6 | session_policy | maintain / tighten / relax / challenge / lockout | 6b |
| — | *provider call* | | |
| 7 | usage_recording | real cost; reservation reconciled | 3 |
| 8 | output_scan | system-prompt leak, echoed redaction tokens | 5 |
| 9 | defense_feedback | leaks become bandit feedback | 6a |
| 10 | audit_log | hash-chained entry on **every** exit path | 7 |

**Fail-closed rule (ADR-0001):** any stage exception → request blocked (503),
unless `FAIL_MODE=open` is explicitly set. Rationale: a failing check that
lets traffic through is a bypass an attacker can trigger.

**Design choice worth stating:** detection only *scores* and never blocks;
the decision belongs to the policy layer. This separation is what makes the
adaptive layer possible.

---

## 7. Methodology — each component (Section IV)

### 7.1 Cost governance

- Token-bucket rate limiter as a Lua script in Redis (atomic).
- **Reserve-then-reconcile budget:** one atomic script reserves the
  estimated cost *and* checks the limit; after the provider answers, the
  reservation is corrected to the real cost; on any failure it is refunded.
- Fixes a race found in testing: 10 concurrent requests against a budget for
  3 → exactly 3 admitted (verified on real Redis).
- HTTP semantics: 402 for exhausted budget, 429 for rate limit.

### 7.2 PII redaction

- Microsoft Presidio (spaCy NER) for names, emails, phones, etc.
- Own regex layer: API keys (`sk-…`, `AKIA…`), credit cards with **Luhn
  check**. Rule: exact-format regex matches beat Presidio on ties.
- Modes: **mask** (`[REDACTED_EMAIL_ADDRESS]`) or **tokenize** (random
  token; original encrypted with Fernet in a vault).
- On by default for every team.
- Hard boundary: only entity-type *counts* (e.g. `{EMAIL_ADDRESS: 1}`) are
  ever stored or logged.
- Covers message content and tool-call arguments (since module 9).

### 7.3 Threat detection classifier

- **Model:** DeBERTa-v3-base, 3 classes (benign, prompt_injection,
  jailbreak), fine-tuned in fp32.
- **Windowed scoring:** each message is split into overlapping windows
  (max sequence length 160, up to 32 windows ≈ 4,000 tokens); the request's
  score is the **worst window**. This defeats a padding attack: 250 tokens
  of filler before an injection scored 0.003 with truncation, 0.997 with
  windows.
- System prompts scored separately (defensive system prompts like "never
  reveal these instructions" otherwise score 0.98 as injection).
- **Calibration:** temperature scaling fitted on validation only,
  T = 2.24 for v2 (attack-score ECE 0.042 → 0.019 on validation).

  Equation: $p = \mathrm{softmax}(z / T)$

- Training: lr 2e-5, effective batch 16 (4 × 4 accumulation), 10% warm-up,
  up to 4 epochs, best epoch by validation macro-F1, class-weighted
  cross-entropy (sqrt-inverse-frequency). Hardware: RTX 3050 Laptop GPU
  (4 GB), ~40 min (v1).

### 7.4 Tactical defence: contextual bandit (LinUCB)

**Why a bandit:** each request is one decision with immediate feedback that
does not change the next request's situation — that is the definition of a
contextual bandit, not RL.

- **Arms (4):** allow, redact_and_allow (cut the suspicious window),
  block, escalate_to_human.
- **Context (9 features, layout v2):** bias, p_injection, p_jailbreak,
  attack log-odds (clipped ±10, /10), system-prompt attack score,
  system × conversation interaction, scan truncated, windows/32, PII count
  (capped 10, /10).
  - Removed in v2 because attackers control them: time of day, team request
    rate (a burst of 60 req/min flipped escalate → redact).
- **Selection (LinUCB, Li et al. 2010):**

  $$a_t = \arg\max_a \; \hat\theta_a^\top x_t + \alpha \sqrt{x_t^\top A_a^{-1} x_t}, \quad \hat\theta_a = A_a^{-1} b_a$$

  with α = 0.5. Updates are **discounted** (γ = 0.999 per arm update) so old
  feedback fades; drift recovery took 144 labels instead of 793.
- **Warm-start prior** (kept separate, never discounted) so day one behaves
  sensibly. Its action bands on the attack score: redact from 0.335,
  escalate from 0.575, block from 0.805.
- **Safety mask:** `allow` is impossible at attack score ≥ 0.99, whatever was
  learned; `redact` masked at ≥ 0.999.
- **Reward table (benign / attack):**

  | Action | Benign | Attack |
  |---|---|---|
  | allow | +1 | −1 |
  | redact_and_allow | +0.5 | 0 |
  | block | −0.3 | +0.5 |
  | escalate | −0.1 | +0.45 |

  (Changed from the plan's draft because the draft made redact and escalate
  never optimal.)
- **Feedback sources:** human verdicts on escalations, a 2% random
  spot-check of other decisions, and output-scan leaks (weighted 0.2).

### 7.5 Strategic defence: DQN session agent

**Why RL:** a session is a sequence; a lockout or challenge changes what
happens to every later request in it, and the payoff is delayed to the end
of the session. That needs states, transitions and delayed reward.

- **Session** = one API key's traffic with gaps < 30 min.
- **State (15 features):** request count; counts of allow / redact / block /
  escalate outcomes; consecutive refusals; last / mean / max attack score
  over recent requests; score slope; share scored ≥ 0.5; redaction frequency;
  current escalation bias; challenge pending. All counts, fractions or
  scores, so the state can never carry text or PII.
- **Actions (5):** maintain; tighten (bias +0.25, bandit stricter); relax
  (bias −0.25); **challenge** (force the next request to human review);
  **lockout** (refuse the key for 15 min; admin can unlock; requires ≥ 2
  refusals).
- **Why challenge/lockout were added (measured first):** even at maximum
  bias, the bandit's decisions change for only ~1% of traffic (scores
  0.2–0.9); 8/190 held-out attacks score < 0.2 and are invisible to any
  score-based rule. Only session-history actions can stop a persistent
  attacker who eventually lands one of those.
- **Reward:** terminal (benign +1.0, or −0.5 if intervened; attack +1.5 if
  intervened, −2.0 if not; any breach −2.0; wrongful lockout −2.0 since
  run 2) + 0.2 × the bandit's per-request reward + potential-based shaping:

  $$F(s, s') = \gamma\,\Phi(s') - \Phi(s), \quad \Phi(s) = c \cdot \max \text{attack score so far}, \; c = 0.5$$

- **Agent:** Stable-Baselines3 DQN, 64–64 MLP, lr 5e-4, 200k–300k steps,
  ε 1.0 → 0.05 over 30%; weights exported to NumPy (the gateway never loads
  pickle).
- **Rule-based fallback (built first):** tighten after 2 consecutive
  refusals, lock out after 4. This is the default policy.
- **Simulator:** real held-out prompts with the production classifier's real
  scores, decided by the bandit's real code; only the session structure
  (lengths, probing, persistence 85%, false-positive-prone users 20%) is
  synthetic.

### 7.6 Tamper-evident audit log

- One entry per request on every exit path (allowed, blocked, failed),
  recording cost, PII counts, threat score, bandit action, session action,
  outcome.
- **Hash chain:**

  $$h_i = \mathrm{SHA256}\big(h_{i-1} \,\|\, \mathrm{canon}(e_i)\big), \quad h_0 = \text{genesis}$$

  `verify` walks the chain and names the first broken entry.
- **Three layers:** ORM guard (app can't update/delete) → Postgres trigger
  (rejects UPDATE/DELETE/TRUNCATE) → restricted role `gateway_app` (INSERT +
  SELECT only on the audit table, cannot disable the trigger) → the hash
  chain still catches a superuser who bypasses all of these.
- **No latency cost:** request enqueues; one background writer chains and
  writes in batches (~940 entries/s measured).

### 7.7 Admin dashboard (brief — 2–3 lines only in the paper)

Next.js, six screens (overview with a "route map" of where requests were
stopped, review queue, audit log with integrity check, threats, cost, PII).
Session token held server-side in an httpOnly SameSite=Strict cookie. Admin
login with scrypt hashes and lockout after 5 failures.

---

## 8. Implementation (Section V — keep short)

| Item | Value |
|---|---|
| Gateway | Python 3.11, FastAPI, Pydantic v2, SQLAlchemy, Alembic |
| Storage | PostgreSQL, Redis |
| ML | HuggingFace transformers (DeBERTa-v3-base), PyTorch, Stable-Baselines3 |
| PII | Microsoft Presidio + spaCy |
| Dashboard | Next.js 16, TypeScript, Recharts, Tailwind |
| Deployment | Docker Compose: one command, migrations and demo seeding automatic (fresh clone up in 81–90 s) |
| Hardware | Laptop, RTX 3050 4 GB GPU for training; CPU inference in Docker |
| Tests | 437 gateway tests (real Postgres + Redis, no skips), 45 dashboard component tests, 16 Playwright browser tests; 97% line+branch coverage of `gateway/app` |

---

## 9. Datasets (Section VI-A)

### 9.1 v1 data (1,913 prompts)

Sources: `deepset/prompt-injections`, `jackhhao/jailbreak-classification`,
`tatsu-lab/alpaca` (benign).

| Split | benign | injection | jailbreak | total |
|---|---|---|---|---|
| train | 799 | 203 | 521 | 1,523 |
| val | 100 | 31 | 65 | 196 |
| test ("old test") | 100 | 29 | 65 | 194 |

### 9.2 Leakage control (important — put it in the paper)

A plain random split left **33 of 91 test attacks as near-copies** of
training rows (jailbreak templates). This inflated injection F1 from 0.81
(true) to 0.87 (reported). Fix: cluster near-duplicates (word 8-gram overlap
≥ 0.5, union-find) and assign whole clusters to one split. Re-check: 0
clusters span train and test.

### 9.3 v2 expansion (added 2026-10-12/13)

| Source | Licence | Used as |
|---|---|---|
| neuralchemy/Prompt-injection-dataset | Apache-2.0 | injection, jailbreak, benign |
| TrustAIRLab/in-the-wild-jailbreak-prompts | MIT | jailbreak; regular prompts as hard benign |
| leolee99/NotInject | MIT | hard benign (trigger words, over-defence) |
| databricks-dolly-15k | CC-BY-SA-3.0 | benign |

Rejected with reasons: SPML (its "attack" label means off-topic), two sets
without a licence, one unlabelled set. 369 template copies dropped.

| Split | Rows | benign | injection | jailbreak |
|---|---|---|---|---|
| train | 6,307 | 3,521 | 1,661 | 1,125 |
| val | 830 | 463 | 226 | 141 |
| **new test (locked, SHA-256 recorded)** | 950 | 546 | 292 | 112 |
| old test | 194 | 100 | 29 | 65 |

---

## 10. Experimental Setup (Section VI-B)

- **Classifier:** precision/recall/F1 per class, macro-F1, benign
  false-positive rate, expected calibration error (ECE). Each model scored
  **once** per test set. Pre-registered criteria for replacing v1: (1) higher
  injection F1 on new test, (2) benign FP rate not higher on new test, (3)
  old-test macro-F1 ≥ 0.913 and benign FP ≤ 0.02.
- **Bandit:** mean reward per request (table in §7.4), attacks allowed,
  benign refused. Baselines: static threshold 0.5; static threshold tuned on
  the *other* split; hindsight-tuned threshold (unachievable ceiling); frozen
  prior. Bandit variants: full feedback (upper bound) and realistic (all
  escalations + 2% spot checks). Experiments: A i.i.d. (2 folds × 30
  orders), B base-rate shift (10% and 2% attacks, 20 streams of 1,000),
  C false-positive drift (20% of benign requests get a score in
  [0.95, 0.995]).
- **Session agent:** return, breach rate (attack sessions with an attack
  allowed), benign friction, benign lockout rate. Baselines: maintain-only
  and the rule. Presets: standard (20% attack sessions), attack-heavy (50%),
  low attack rate (5%), shifted (longer sessions, more FP-prone users,
  adaptive attacker). Paired sessions, 95% CI on the return difference.
  **Go/no-go criterion written before training:** beat both baselines on
  every preset (CI > 0) and benign lockout ≤ rule + 1 point.

---

## 11. Results (Section VII) — tables ready to use

### Table I — Classifier v1, old test (194, leak-free)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 0.94 | 0.99 | 0.97 | 100 |
| prompt_injection | 0.89 | 0.83 | 0.86 | 29 |
| jailbreak | 1.00 | 0.95 | 0.98 | 65 |
| macro avg | 0.94 | 0.92 | 0.93 | 194 |

### Table II — Generalisation: v1 vs v2 vs v3 (the key classifier result)

| Metric | v1 | v2 (shipped) | v3 |
|---|---|---|---|
| New test (950) macro-F1 | 0.490 | **0.908** | 0.877 |
| New test injection F1 | 0.341 | **0.949** | 0.935 |
| New test jailbreak F1 | 0.335 | **0.805** | 0.740 |
| New test benign FP rate | 0.275 | **0.031** | 0.042 |
| Old test (194) macro-F1 | **0.933** | 0.884 | 0.871 |
| Old test injection F1 | **0.857** | 0.769 | 0.759 |
| Old test benign FP rate | 0.010 | 0.010 | 0.030 |

Attack-vs-benign, both tests combined (498 attacks, 646 benign):

| | attacks missed | benign flagged |
|---|---|---|
| v1 | 63 (12.7%) | 151 (23.4%) |
| v2 | 28 (5.6%) | 18 (2.8%) |
| v3 | 36 (7.2%) | 26 (4.0%) |

**Honest note to write in the paper:** v2 failed pre-registered criterion 3
(old-test macro-F1 0.884 < 0.913; the gap is 6 attacks on 194 rows). The
team shipped it anyway as a recorded override, because on the 5× larger test
v1 flags 27.5% of benign prompts. State it exactly like this. It reads as
mature, not as a weakness.

### Table III — Inference latency

| Device | Short prompt | ~1,000 tokens |
|---|---|---|
| RTX 3050 Laptop GPU | 20–60 ms | ~90 ms |
| CPU | 160–230 ms | ~1.5 s |

### Table IV — Bandit, Experiment A (i.i.d., v1 scores)

| Policy | Mean reward | Attacks allowed | Benign refused |
|---|---|---|---|
| static@0.5 | 0.722 | 4.2% | 0.5% |
| static-tuned | 0.719 | 4.2% | 1.0% |
| prior-frozen | 0.722 | 4.2% | 0.5% |
| bandit (full) | 0.714 | 4.2% | 0.5% |
| bandit (realistic) | 0.721 | 4.2% | 0.5% |

→ **A tie.** Reason: scores are bimodal (168/190 attacks ≥ 0.999, 195/200
benign < 0.01); the 4.2% missed attacks score < 0.5, mostly < 0.01, so no
policy on the score can catch them.

### Table V — Bandit, Experiment C (false-positive drift, v1 scores)

| Policy | Mean reward | Attacks allowed | Benign refused |
|---|---|---|---|
| static-tuned | 0.697 | 4.7% | 21.0% |
| static-hindsight (ceiling) | 0.905 | 7.6% | 2.8% |
| prior-frozen | 0.703 | 4.7% | 20.5% |
| bandit (full feedback) | **0.837** | 4.7% | **0.9%** |
| bandit (2% spot checks) | 0.739 | 4.7% | 15.1% |

Spot-check rate vs gain: 2% → 0.739, 5% → 0.792, 10% → 0.820, 25% → 0.832
(a good small figure: reward vs labelling budget).

### Table VI — Bandit re-check with v2 scores (be honest about this one)

| Experiment | Data | static-tuned | bandit (realistic) | Δ |
|---|---|---|---|---|
| A i.i.d. | new | 0.696 | 0.697 | +0.001 |
| B 10% attacks | new | 0.871 | 0.850 | −0.020 |
| B 2% attacks | new | 0.910 | 0.886 | −0.024 |
| C drift | new | 0.651 | 0.657 | +0.007 |

Full feedback on drift still wins (+0.111 on new data). Cause of the losses:
the prior's band edges were designed when scores were all-or-nothing; v2's
calibrated scores land in the middle bands, and 2% feedback is too slow to
move them (L6a-30). Future work: re-fit band edges on validation.

### Table VII — Session agent, run 2 (standard preset, 3,000 sessions, 5 seeds)

| Policy | Return | Breach | Benign lockout |
|---|---|---|---|
| maintain | 1.678 | 19.3% | 0.0% |
| rule | 1.943 | 14.4% | 0.8% |
| DQN (mean of 5) | **2.077** | **9.9%** | 0.9% |

Result: 3/5 seeds pass (4 needed) → NO-GO. Misses only at 5% attack rate.

### Table VIII — Session agent, run 3 (20,000 sessions/preset, 3 ensembles of 5 DQNs, v2 scores)

| Preset | maintain | rule | ensembles | rule lockout | ensemble lockout |
|---|---|---|---|---|---|
| standard | 1.569 | 1.779 | 1.838–1.860 | 1.2% | 3.1–3.5% |
| attack-heavy | 0.390 | 1.257 | 1.556–1.567 | 1.3% | 3.1–3.5% |
| low attack rate | 2.153 | 2.040 | 1.974–1.999 | 1.2% | 3.1–3.5% |
| shifted | 2.220 | 2.019 | 2.175–2.208 | 7.4% | 6.6–7.9% |

Breach on standard: ensembles 8.3%, rule 11.7%, maintain 16.7%.
**NO-GO:** lockout limit (rule + 1 pt = 2.2%) exceeded. Cause: checkpoint
selection estimated lockout on only 600 validation sessions (~10–15 events),
so it picked checkpoints that looked safe by chance (winner's curse).

### Summary across RL runs (good for one compact table)

| Run | Change | Seeds/ensembles passing | Failure cause |
|---|---|---|---|
| 1 | baseline, ± shaping | 2/5 shaped, 0/5 unshaped | wrongful lockouts 2–5× rule; 2 unshaped collapsed |
| 2 | wrongful lockout −2.0, lockout needs 2 refusals, validation checkpointing | 3/5 | not provably better than doing nothing at 5% attacks |
| 3 | v2 scores, mixed attack rates, 5-DQN voting ensembles, 20k sessions | 0/3 | benign lockout 3.1–3.5% > 2.2% limit |

Finding worth highlighting: potential-based shaping, which theoretically
doesn't change the optimal policy, made training much more stable (0/5 vs
2/5 collapses).

### Security results (qualitative, plus test counts)

- Live end-to-end run (gateway → local Llama 3 via Ollama): a PII email was
  redacted before the model saw it — the model's reply literally contains
  `[REDACTED_EMAIL_ADDRESS]`; audit log holds only `{EMAIL_ADDRESS: 1,
  PHONE_NUMBER: 1}`; "Ignore all previous instructions…" blocked; hash chain
  valid over 145 entries.
- Tamper demo: editing one entry from "block" to "allow" in Postgres is
  detected and the entry named; from the restricted role the edit is
  refused outright (*permission denied*).
- Security-boundary tests plant an email, phone, card, SSN and fake keys,
  then search every table, Redis key, DEBUG log line, response and upstream
  request. They found and fixed: Presidio's own logger writing raw text at
  DEBUG; provider error text echoing keys to clients; tool-call arguments
  bypassing every check.
- Throughput: ~9 requests/s, 100 concurrent requests all complete (after
  fixing a per-request HTTPS client that capped it at ~3 req/s).

---

## 12. Discussion (Section VII-end) — key arguments

1. **Benchmarks can mislead.** v1 scored 0.933 on its own test and 0.490 on
   a larger, more varied one. Small, narrow test sets inflate confidence.
2. **A policy can't fix the detector's blind spots.** The bandit adds
   adaptivity, not accuracy; it helps exactly when errors are concentrated
   in a score band that feedback can reveal.
3. **Separating detection from response pays off** even when learning
   doesn't win: it gives a safety mask, human escalation, and a place to
   plug in session memory.
4. **Downstream components are tuned to upstream behaviour.** Better
   calibrated scores (v2) exposed assumptions in the bandit's prior that
   were silently fitted to v1's all-or-nothing scores.
5. **RL found a real effect (fewer breaches via session memory) but not
   reliably enough.** The bottlenecks are the reward design and data/
   statistical power, not the algorithm. A safety constraint needs as much
   statistical power as the objective it constrains.
6. **Pre-registration mattered.** It stopped us from re-running on the same
   test set until something passed, and it is why the override of one
   criterion is visible rather than hidden.

---

## 13. Limitations (Section VIII — pick the important ones)

- Detection evaluated only on public benchmarks; no adaptive red-team
  attacker (L5-7, L9-5).
- False positives on very short or imperative text: "hello" scores 0.805,
  "No results." 0.903; SQL in tool arguments 0.976 (L5-2, L9-2).
- Some request fields (`name`, `user`, tool definitions, `response_format`)
  are forwarded unchecked (L9-1).
- Output scan catches only verbatim system-prompt leaks, not paraphrased or
  encoded ones (L5-3).
- RL trained and evaluated in a simulator with synthetic session structure
  (L6b-3); a "session" is an API key, so a shared key means one attacker
  can lock out all its users (L6b-1).
- Reward tables are hand-designed proxies, not measured costs (L6a-8).
- Streaming responses not supported — rejected by design so the whole
  answer can be inspected first (L2-3).
- Single-node demo: ~9 req/s on CPU, no load testing, no TLS/secret manager
  (L9-4, L10-5). A crash can lose a few queued audit entries (L7-1); deleting
  the newest entries isn't detectable by the chain alone (L7-2).

## 14. Future Work

- Re-fit the bandit's prior bands to calibrated scores (pre-registered).
- Larger validation set (≥ 5,000 sessions) or a constrained-RL formulation
  for the lockout limit; train on real logged sessions instead of the
  simulator.
- Adaptive red-team loop that mutates blocked prompts.
- Semantic leak detection (embeddings), streaming via buffer-scan-replay.
- ONNX/GPU inference and load testing; Thompson sampling with logged
  propensities for off-policy evaluation.

## 15. Conclusion (draft)

> We built and evaluated a fail-closed LLM gateway that combines cost
> control, PII redaction, injection detection, a two-tier adaptive defence
> and tamper-evident auditing. The classifier reaches macro-F1 0.908 on a
> locked 950-prompt test, and the evaluation showed that a smaller benchmark
> had overstated an earlier model. The contextual bandit costs nothing where
> the classifier is right and recovers from drift where it is wrong, but
> can't correct the detector's blind spots. The DQN session agent reduced
> breaches relative to a rule-based policy but did not meet a pre-registered
> safety criterion, so the rule remains the default. We argue that such
> negative results, reported with their causes, are as useful to
> practitioners as positive ones.

## 16. Acknowledgment

Thank Mr. Monish L (guide) and the Department / institution. Mention the
dataset authors (deepset, jackhhao, TrustAIRLab, NotInject, neuralchemy,
Databricks, Stanford Alpaca) if space allows.

---

## 17. Figures and tables to prepare

| # | Figure / table | Source |
|---|---|---|
| Fig. 1 | Deployment architecture | §6.1, `diagram.png` |
| Fig. 2 | Request pipeline with stage order | §6.2 |
| Fig. 3 | Two-tier defence: bandit per request, DQN per session | §7.4–7.5 |
| Fig. 4 | Hash chain diagram (h₀ → h₁ → h₂, tampered entry breaks link) | §7.6 |
| Fig. 5 | Bandit learning curve under drift / reward vs spot-check rate | Table V numbers |
| Fig. 6 | Breach rate vs benign lockout for maintain / rule / DQN (scatter, one point per policy) | Tables VII, VIII |
| Tab. | Tables II, V, VII/VIII and the RL-run summary are the essential ones | §11 |

Optional: a dashboard screenshot (route map) — only one, and only if space.

## 18. If you have time before submission: one experiment that would make the paper much stronger

The biggest gap a reviewer will point at is **no comparison with an
existing guard model**. Running one or two public detectors (e.g. a public
prompt-injection DeBERTa classifier, or Llama Guard) on the same locked
950-row test and reporting their macro-F1 and benign FP rate next to v2
would turn Table II into a proper comparison. Report it honestly even if
they win — then your contribution is the system and the adaptive layer,
not the detector.

## 19. Practical notes

- Use the official IEEE conference template (two-column, 10 pt). 6 pages is
  typical for a conference paper; check your target's limit.
- References in IEEE numbered style `[1]`; 15–25 references is enough.
- Don't put code, installation steps, or every module's bug story in the
  paper. Those belong in the project report. Keep at most 2–3 "lessons" as
  discussion points (leakage, pre-registration, calibration effect).
- Every number in the paper should be traceable to `training/README.md` or
  `LIMITATIONS.md`. If an examiner asks "where does 0.908 come from?" you
  should be able to open the file and show it.
