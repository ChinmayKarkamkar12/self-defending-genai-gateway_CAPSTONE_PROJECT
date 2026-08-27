# Module 6b: Adaptive Defense — Strategic Layer (Reinforcement Learning, per-session)

**Depends on:** Module 1 (repo), Module 2 (pipeline), Module 5 (threat scores), **Module 6a must be complete and its Definition of Done met before starting this file** — this module consumes 6a's action history as state and writes into 6a's `escalation_bias` hook
**Feeds into:** Module 7 (audit log records session-level policy shifts), Module 8 (dashboard gets a session-risk view)
**This is the RL component matching your submitted proposal's "RL agent design: state/action/reward/training environment." Budget real time here — this is the highest-risk module in the whole plan.**

## 1. Purpose & scope

Module 6a's bandit is correct for a single isolated request, but real attackers often don't attack in one shot — they probe, get partial signal back, rephrase, escalate over several requests in a session. That's a genuinely **sequential decision problem**: today's response shapes what the attacker (or a legitimate user who tripped a false positive) does next, and the "right" policy depends on the accumulated pattern, not just the current request in isolation. That sequential, state-dependent, delayed-reward structure is exactly what reinforcement learning is built for — this module is where RL actually fits the problem, rather than being forced onto something that didn't need it.

**In scope:** MDP formulation, session state tracking, a training simulator (you cannot safely explore on live traffic), a DQN agent, offline training + evaluation against a baseline, integration with module 6a via the `escalation_bias` hook, and an explicit fallback plan if training doesn't converge in time.
**Out of scope:** per-request decisions (that's 6a's job — this module never picks 6a's action directly, only nudges its bias) and the adversarial red-team loop (still the stretch goal shared with 6a, section 11 of that file).

## 2. MDP formulation

**Episode = one session.** Define a session as: all requests from one API key within a rolling inactivity window (default 30 minutes — configurable). A session ends when the window expires or the key is explicitly locked out. This is a deliberate, documented choice — the gateway doesn't see application-level user sessions, only API-key-level traffic, so this is the closest honest proxy available. Say so plainly in your report rather than implying you have finer-grained visibility than you do.

**State `s_t`** (feature vector, rebuilt on each new request in the session):
| Feature | Description |
|---|---|
| `action_counts` | count of each 6a bandit action so far this session (allow/redact/block/escalate) |
| `threat_score_trend` | rolling mean and slope of module 5's threat scores across the session |
| `redaction_frequency` | fraction of requests this session that triggered PII redaction (module 4) |
| `request_rate` | requests per minute in this session so far |
| `session_age` | time since session start |
| `budget_fraction_remaining` | from module 3 — a session burning budget fast is itself a signal |
| `current_escalation_bias` | the session's current value of 6a's threshold hook (so the agent knows its own prior action's effect) |

**Action space `a_t`** (session-level policy moves, distinct from 6a's per-request actions):
| Action | Effect |
|---|---|
| `maintain` | leave `escalation_bias` unchanged |
| `tighten` | raise `escalation_bias` — module 6a becomes more cautious for subsequent requests in this session |
| `relax` | lower `escalation_bias` — reduces friction once a session looks clearly benign |
| `challenge` | force the next request in this session through the human-review queue (module 6a's `escalate_to_human`), regardless of that request's individual threat score |
| `lockout` | suspend the API key for this session (hard stop), pending manual review |

**Reward `r_t`** — this is the part most likely to go wrong if you don't design it deliberately, so be explicit about the reasoning, not just the numbers:
- Reward is mostly **delayed**, resolved at session end or whenever ground truth becomes available (a human review decision, or a later-confirmed incident):
  - `+1.0`: correctly maintained/relaxed through a confirmed-benign session (low friction preserved)
  - `-0.5`: tightened/challenged/locked out a confirmed-benign session (unnecessary friction — this penalty exists specifically so the agent doesn't learn "when in doubt, lock everything down," which would technically maximize safety but destroy usability)
  - `+1.5`: tightened/challenged/locked out a session later confirmed as an attack
  - `-2.0`: maintained/relaxed through a session later confirmed as an attack (worst outcome, weighted heaviest)
- To avoid reward sparsity slowing training down (waiting until session end for every learning signal is slow), add a **small immediate shaping term** at each step: a fraction of module 5's threat score change, so the agent gets *some* signal before the session resolves. Document this shaping term separately from the terminal reward so you can ablate it in your evaluation (i.e., show training with vs. without shaping) — that comparison is a good thing to have in your report regardless of which way it turns out.

## 3. Training environment (the simulator — build this before the agent)

You cannot let an untrained agent explore by locking out real users, so training happens entirely offline against a simulator. This is the highest-effort, highest-risk piece of this module — budget real time for it.

```
training/rl_env.py            # Gym-style: reset(), step(action) -> (state, reward, done, info)
training/generate_sessions.py # builds synthetic session sequences from module 5's labeled prompt dataset
```

`generate_sessions.py` approach: sample sequences of 3–15 individual labeled prompts (reusing module 5's benign/injection/jailbreak dataset) into synthetic "sessions," with two session archetypes:
- **Benign session**: mostly benign prompts, occasional false-positive-prone phrasing mixed in
- **Attack session**: starts benign or ambiguous, escalates toward confirmed injection/jailbreak prompts over the sequence — this mimics the "attacker probes then escalates" pattern that's the whole justification for this module existing

`rl_env.py`'s `step(action)` needs to simulate what module 6a's bandit *would have decided* under the current `escalation_bias`, since you're not running the real bandit live during training — reuse module 6a's actual decision function against the simulated `escalation_bias` value, so the simulator stays faithful to production behavior rather than being a separate reimplementation that could drift from it.

## 4. Algorithm

Use **DQN** (Deep Q-Network) — a small MLP (2–3 hidden layers, ~64–128 units) is enough given the state vector size and 5-action discrete space; this doesn't need a large network. Use **`stable-baselines3`** rather than a fully custom implementation — it handles the experience replay buffer, target network, and epsilon-greedy exploration schedule correctly, which removes a large class of subtle RL bugs that would otherwise eat your timeline. Reserve engineering effort for the environment and reward design, not for reimplementing DQN internals.

```
training/train_rl_agent.py    # stable-baselines3 DQN training loop against rl_env.py
training/evaluate_rl_agent.py # runs the trained policy against held-out simulated sessions
```

## 5. Integration with module 6a

- `SessionState` store in Redis (ephemeral, session-scoped): holds the current feature vector and current `escalation_bias`
- The RL policy doesn't run per-request (too slow for the fast path) — it runs **periodically**: every N requests in a session, or every T seconds, whichever comes first. On each trigger, it reads `SessionState`, computes an action, and writes the new `escalation_bias` back to Redis.
- Module 6a's bandit stage reads `escalation_bias` from `SessionState` (falls back to 0.0 / neutral if no session state exists yet) before selecting its per-request action — this is the one read/write contract between the two modules, keep it that narrow.

## 6. Fallback plan — decide this now, not during crunch

RL training instability is the single biggest risk in this entire project plan. Commit to a concrete go/no-go checkpoint: **by the date set in the roadmap (module 11), if `evaluate_rl_agent.py` doesn't show a clear, reproducible improvement over the "maintain-only" baseline, swap in a rule-based session-escalation policy instead** — e.g., "tighten after 2 consecutive non-allow bandit actions in a session, lockout after 4." Build this rule-based policy now, behind the same interface (reads `SessionState`, writes `escalation_bias`), so swapping it in is a one-line change, not a rewrite. This means the project still ships a working, demoable strategic layer even if DQN training runs out of time — and you can honestly report "we attempted RL, validated it against a rule-based fallback, and here's what we found," which is a legitimate research narrative either way.

## 7. Implementation tasks

1. [ ] Define session identification in `app/core/defense/session.py` (API key + rolling window)
2. [ ] Write `app/core/defense/rl/features.py` — state feature extraction from session history
3. [ ] Write `training/generate_sessions.py` — synthetic benign/attack session generator from module 5's dataset
4. [ ] Write `training/rl_env.py` — Gym-style environment, reusing module 6a's real decision function for simulated bandit behavior
5. [ ] Write the rule-based fallback policy (`app/core/defense/rl/fallback_policy.py`) **before** starting DQN training — this de-risks the module immediately
6. [ ] Write `training/train_rl_agent.py` using `stable-baselines3`'s DQN
7. [ ] Write `training/evaluate_rl_agent.py` — compare trained agent vs. "maintain-only" baseline vs. the rule-based fallback, on held-out simulated sessions; report cumulative reward, attack-catch rate, and false-positive-friction rate for all three
8. [ ] Apply the go/no-go decision from section 6 using the roadmap's checkpoint date
9. [ ] Write `app/core/defense/rl/policy.py` — loads whichever policy won (trained DQN or fallback), runs on the periodic trigger, updates `SessionState`
10. [ ] Wire the periodic trigger into the request pipeline (a lightweight check alongside module 6a's stage, not blocking it)
11. [ ] Expose `GET /v1/admin/sessions/{id}/risk-trend` for module 8's dashboard

## 8. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_session.py::test_session_id_stable_within_window` | Unit | requests within the inactivity window map to the same session; a request after the window starts a new one |
| `test_features.py::test_feature_vector_shape_and_ranges` | Unit | state vector has the documented fields, values in sane ranges |
| `test_rl_env.py::test_episode_terminates_correctly` | Unit | a scripted session sequence ends the episode at the expected step |
| `test_rl_env.py::test_reward_matches_documented_table` | Unit | reward output matches section 2's reward table for known outcome combinations |
| `test_fallback_policy.py::test_tightens_after_consecutive_flags` | Unit | fallback policy behaves exactly as documented in section 6 |
| `evaluate_rl_agent.py` run | Offline evaluation | trained DQN vs. maintain-only baseline vs. rule-based fallback, on held-out simulated sessions — **this three-way comparison is your headline RL result for the report** |
| `test_integration.py::test_bias_written_and_read_correctly` | Integration | 6b writes `escalation_bias` to `SessionState`, 6a's bandit stage reads and applies it on the next request |
| `test_integration.py::test_fallback_swap_is_config_only` | Integration | swapping the active policy from DQN to fallback (or vice versa) requires no code change to the pipeline, only a config flag |

## 9. Definition of done

- [ ] Simulator built and validated against scripted test sessions
- [ ] Rule-based fallback implemented, tested, and ready to activate via config — **do this regardless of whether DQN training succeeds**
- [ ] DQN trained (or the go/no-go decision explicitly made and documented if it didn't converge in time)
- [ ] Three-way evaluation (DQN vs. baseline vs. fallback) documented with real numbers
- [ ] Integration with module 6a verified end to end
- [ ] All tests pass; `ruff check` clean
