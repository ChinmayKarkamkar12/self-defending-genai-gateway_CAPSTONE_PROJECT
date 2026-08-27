# Module 6a: Adaptive Defense — Tactical Layer (Contextual Bandit, per-request)

**Depends on:** Module 1 (repo), Module 2 (pipeline hook interface), Module 5 (threat scores this module consumes)
**Feeds into:** Module 6b (the RL strategic layer adjusts this module's thresholds), Module 7 (audit log records the action taken + later feedback), Module 8 (dashboard shows human-review queue and policy performance over time)
**Part of the project's core novel contribution — see Module 6b for the other half.**

## 0. Where this fits in the hybrid design

The adaptive defense layer is now built as **two coordinated tiers**, not one:

| Tier | Scope | Algorithm | File |
|---|---|---|---|
| **Tactical** (this file) | Per single request | Contextual bandit | `06a-adaptive-defense-bandit.md` |
| **Strategic** | Per session (sequence of requests) | Reinforcement learning (DQN) | `06b-adaptive-defense-rl-session-agent.md` |

This module — the bandit — makes the fast, per-request call (allow/redact/block/escalate) using the threat score from module 5. It runs on every single request and must stay low-latency and stable. The RL agent in module 6b watches sequences of these bandit decisions across a session and periodically adjusts this module's decision thresholds — tightening them when a session looks like an evolving, multi-step attack, relaxing them when a session looks clearly benign to reduce unnecessary friction. Build and get this tactical layer fully working and tested **first** — module 6b explicitly depends on this one being stable, since it consumes this module's action history as part of its state.

## 1. Purpose & scope

This is a **contextual bandit** learning a response *policy* (what action to take given a threat score + context) for a single request. It's the right algorithm for this specific decision because it's genuinely single-step: one context in, one action out, one reward back — no notion of the decision changing a future state, which is what module 6b's session-level RL layer is for instead.

**In scope:** bandit implementation, action space, reward signal design, feedback loop (including a human-review queue for uncertain cases), online policy updates, and a threshold-adjustment interface that module 6b can call into.
**Out of scope:** anything session-level or sequential — that's entirely module 6b's job.

## 2. Problem framing

- **Context** (the "state" the bandit observes): threat score from module 5 (`benign`/`injection`/`jailbreak` probabilities), which team/API key is asking, time-of-day / request-rate features, whether PII was detected in the same request (module 4's output)
- **Actions**: `allow`, `redact_and_allow` (strip anything that looks risky but let it through), `block`, `escalate_to_human` (hold the request, queue it for a human reviewer, default to blocking while it waits)
- **Reward**: this is the part to design carefully, since you don't get real reward signal instantly.
  - Immediate proxy reward: a hand-authored reward function used for the demo/evaluation phase, e.g. +1 for correctly allowing benign traffic, -1 for allowing a confirmed attack through, -0.3 for blocking benign traffic (false positive cost), +0.5 for correctly blocking a confirmed attack.
  - Delayed real reward: human-review outcomes on `escalate_to_human` cases feed back as labeled reward once reviewed — this is your genuine online-learning loop, not just a static replay.

## 3. Algorithm choice

Use a standard contextual bandit algorithm rather than inventing one — **LinUCB** or **Thompson Sampling with a linear reward model** are both well-documented, implementable in under a day, and explainable to faculty (you can show the confidence bounds / posterior directly, which is a good demo visual for module 8's dashboard). Don't reach for deep RL here — it adds training instability and debugging time you don't have, and it wouldn't be more "correct" for this action space size (4 actions). Reserve deep RL for module 6b, where it fits a genuinely sequential problem.

**Threshold-adjustment hook (this is the join point with module 6b):** expose a small mutable setting per session — e.g. `escalation_bias: float` (default 0.0) — that shifts the bandit's action thresholds up or down. Module 6b writes to this value in the session store (see module 6b section 5); this module only needs to *read* it before selecting an action. Keep this interface narrow and one-directional: 6a never reads 6b's internal state, 6b never picks 6a's action directly, it only nudges the bias.

```
app/core/defense/
  bandit.py          # LinUCB or Thompson Sampling implementation
  features.py         # context vector construction from RequestContext.metadata
  reward.py            # proxy reward function + interface for delayed real reward
  review_queue.py      # escalate_to_human queue management
```

## 4. Data model additions

```
ThreatEvent   (Postgres)
  id: uuid (pk)
  request_id: uuid
  threat_score: jsonb       # from module 5
  context_features: jsonb   # what the bandit saw
  action_taken: enum(allow, redact_and_allow, block, escalate_to_human)
  bandit_confidence: float
  reward_applied: float | null    # filled in once known
  human_label: enum(attack, benign) | null    # filled in by review queue
  created_at: timestamp

ReviewQueueItem   (Postgres)
  id: uuid (pk)
  threat_event_id: uuid (fk)
  status: enum(pending, reviewed)
  reviewer: str | null
  decision: enum(attack, benign) | null
  reviewed_at: timestamp | null
```

## 5. Pipeline stage contract

`bandit_policy_stage.process(ctx)` — runs immediately after `threat_detection_stage`:
1. Build context vector from `ctx.metadata["threat_score"]` + other features
2. Query the bandit for an action (with exploration, per the algorithm's own logic — don't disable exploration for the demo, that defeats the point of showing it's adaptive)
3. Write a `ThreatEvent` row recording context + action + confidence
4. Map action to a `StageResult`:
   - `allow` → `ALLOW`
   - `redact_and_allow` → `MODIFY` (strip flagged spans, similar mechanism to module 4)
   - `block` → `BLOCK`
   - `escalate_to_human` → `BLOCK` for now (safe default), create a `ReviewQueueItem`
5. When a `ReviewQueueItem` is later resolved (via the admin API, surfaced in module 8's dashboard), compute the reward and call `bandit.update(context, action, reward)` — this is the actual "adaptive" part, the policy weights change after this call

## 6. API contract

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/review-queue` | pending items for human review |
| `POST /v1/admin/review-queue/{id}/decide` | reviewer submits `attack`/`benign`, triggers bandit update |
| `GET /v1/admin/bandit/stats` | action distribution over time, cumulative reward trend — feeds module 8's "policy performance" chart |

## 7. Implementation tasks

1. [ ] Add `ThreatEvent` and `ReviewQueueItem` models + migration
2. [ ] Write `app/core/defense/features.py` — context vector construction, documented feature list
3. [ ] Write `app/core/defense/bandit.py` — implement LinUCB (or Thompson Sampling), with `.select_action(context)` and `.update(context, action, reward)`, persisting learned parameters to Postgres or Redis so they survive restarts
4. [ ] Write `app/core/defense/reward.py` — the proxy reward function, documented with the reasoning behind each weight
5. [ ] Write `app/core/defense/review_queue.py`
6. [ ] Write the real `bandit_policy_stage`
7. [ ] Write the three admin endpoints above
8. [ ] Write an offline evaluation harness (`training/evaluate_bandit.py`) that replays a labeled test set (mix of known-attack and known-benign prompts, reuse module 5's held-out test set) through the bandit and reports cumulative reward vs. a static-threshold baseline — **this comparison is your headline result for the faculty presentation**, so budget time to make it clean

## 8. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_bandit.py::test_action_selection_deterministic_given_seed` | Unit | with a fixed random seed, action selection is reproducible (essential for debugging) |
| `test_bandit.py::test_update_changes_future_action_probabilities` | Unit | after repeated negative reward for `allow` in a given context, the bandit's confidence in `allow` for similar contexts decreases — this is the core "it's actually adaptive" test |
| `test_reward.py::test_reward_values_match_documented_weights` | Unit | reward function output matches the documented weight table for each outcome combination |
| `test_bandit_stage.py::test_escalate_creates_review_item` | Unit | `escalate_to_human` action creates a `ReviewQueueItem` and blocks by default |
| `test_review_queue.py::test_decision_triggers_bandit_update` | Integration | submitting a review decision calls `bandit.update()` with the correct reward |
| `evaluate_bandit.py` run | Offline evaluation | cumulative reward of the bandit policy vs. a static-threshold baseline on the held-out set — **document this comparison, don't just eyeball it** |

## 9. Definition of done

- [ ] Bandit demonstrably changes behavior after feedback (the adaptivity test passes)
- [ ] Review queue round-trips end to end
- [ ] Offline evaluation comparing bandit vs. static threshold is written up with numbers — this is your differentiation evidence for the faculty presentation
- [ ] All tests pass; `ruff check` clean

## 10. What comes next

Once this tactical layer meets its Definition of Done, move to **`06b-adaptive-defense-rl-session-agent.md`** — the reinforcement-learning strategic layer that consumes this module's action history as part of its state and writes back to the `escalation_bias` hook above.

## 11. Stretch goal (track separately, don't block core delivery on this)

A small adversarial red-team loop: a script that generates paraphrased/obfuscated variants of known attacks, runs them through the current pipeline, logs what got through, and feeds those as additional training signal for both this module and 6b. Even a toy version (10–20 generated variants per week during the build phase) gives you a genuine "adversarial retraining" story for the report's future-work section, tying back to the RETA/ARLAS research direction from the evidence base.
