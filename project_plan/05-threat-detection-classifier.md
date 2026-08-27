# Module 5: Threat Detection Classifier (Prompt Injection / Jailbreak — Layer 1)

**Depends on:** Module 1 (repo), Module 2 (pipeline hook interface, `threat_detection_stage` and `output_scan_stage` stubs)
**Feeds into:** Module 6 (the bandit's context features come from this classifier's scores), Module 7 (audit log records threat scores)
**Can be built in parallel with:** Module 3, Module 4

## 1. Purpose & scope

This is Layer 1 of the adaptive defense system — a supervised ML classifier that scores every incoming prompt for injection/jailbreak likelihood, and a lighter output-side scanner that checks the LLM's response for leakage. This module produces a **score**, not a final action — module 6 decides what to *do* with the score. Keep that boundary clean: this module never blocks anything itself.

**In scope:** classifier fine-tuning, inference service, output-side leakage scan.
**Out of scope:** deciding block/allow/redact (module 6), the adversarial red-team loop (stretch goal, tracked separately, not in this file).

## 2. Data & training approach

Don't train from zero. Start from public datasets:
- `deepset/prompt-injections` (HuggingFace) — labeled prompt injection examples
- JailbreakBench / a curated jailbreak prompt collection for the jailbreak class
- Generate additional negative (benign) examples from a general instruction-following dataset so the classifier doesn't just learn "any unusual phrasing = attack"

Fine-tune a small transformer — `microsoft/deberta-v3-base` is a reasonable choice given the compute available to a student team (don't reach for the large variant unless GPU time is genuinely free). Frame it as 3-class: `benign`, `prompt_injection`, `jailbreak`.

Training happens **offline**, in a separate `training/` directory outside the gateway service — this is a one-time (or periodically-repeated) job, not something that runs inside the request path.

```
training/
  prepare_dataset.py     # pulls + merges the public datasets, splits train/val/test
  train_classifier.py    # fine-tunes DeBERTa, saves checkpoint
  evaluate.py             # precision/recall/F1 per class on held-out test set
  export_onnx.py          # optional: export to ONNX for faster inference (ties to your existing TensorRT/ONNX/Triton experience)
```

## 3. Inference service

The trained model gets loaded once at gateway startup (not per-request) and served through a small internal module:

```python
class ThreatClassifier:
    def score(self, text: str) -> ThreatScore:
        """Returns {benign: float, prompt_injection: float, jailbreak: float}"""
```

For the demo environment, run inference on CPU if a GPU isn't available in the deployment target — document the expected latency difference in the README (CPU inference on a base-sized DeBERTa is usually acceptable for a low-QPS demo, but call this out explicitly rather than assuming).

## 4. Pipeline stage contracts

`threat_detection_stage.process(ctx)` (pre-call):
1. Run `ThreatClassifier.score()` on the prompt
2. Attach `ctx.metadata["threat_score"] = {...}` — always ALLOW at this stage; **do not block here**. Module 6's bandit stage (which runs immediately after this one in the pipeline) is the only place that decides the action. This module's job ends at producing a trustworthy score.

`output_scan_stage.process(ctx)` (post-call, on the provider's response):
1. Run a lighter check on the response: does it contain the system prompt verbatim (system-prompt leakage), or does it contain any of the redaction tokens from module 4 in a way that suggests the model echoed something it shouldn't have?
2. Attach `ctx.metadata["output_flags"]`
3. This stage can return `BLOCK` directly (replace the response with a generic refusal) if leakage is detected with high confidence — this one's binary enough not to need the bandit's judgment call.

## 5. Implementation tasks

1. [ ] Write `training/prepare_dataset.py` — pull and merge the datasets, produce train/val/test splits, save to `training/data/`
2. [ ] Write `training/train_classifier.py` — fine-tune DeBERTa on the 3-class task, save checkpoint to `training/checkpoints/`
3. [ ] Write `training/evaluate.py` — report precision/recall/F1 per class on the held-out test set; **write these numbers into the module's README as they'll go straight into the faculty report**
4. [ ] Write `app/core/threat/classifier.py` — loads the trained checkpoint, exposes `ThreatClassifier.score()`
5. [ ] Write the real `threat_detection_stage` (score-only, no blocking) replacing the module-2 stub
6. [ ] Write `app/core/threat/output_scan.py` — system-prompt leakage check + redaction-token echo check
7. [ ] Write the real `output_scan_stage` replacing the module-2 stub
8. [ ] Add a startup hook in `app/main.py` to load the model once, not per-request

## 6. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `evaluate.py` run | Offline evaluation | precision/recall/F1 per class ≥ a documented target (pick a realistic target after seeing your first run, e.g. F1 ≥ 0.85 on injection class — don't invent an ungrounded number before training) |
| `test_classifier.py::test_scores_sum_reasonably` | Unit | classifier output is a valid probability-like distribution |
| `test_classifier.py::test_known_injection_scores_high` | Unit | a canonical injection example ("ignore previous instructions...") scores high on the injection class |
| `test_classifier.py::test_known_benign_scores_low` | Unit | an ordinary question scores low on both attack classes |
| `test_threat_stage.py::test_stage_never_blocks` | Unit — **architecturally important, don't skip** | assert this stage's `StageResult` is always `ALLOW`, regardless of score, to enforce the score/action boundary with module 6 |
| `test_output_scan.py::test_detects_system_prompt_echo` | Unit | a mocked response that includes the system prompt verbatim is flagged |
| `test_output_scan.py::test_detects_redaction_token_echo` | Unit | a mocked response echoing a `[REDACTED_...]` token from module 4 is flagged |

## 7. Definition of done

- [ ] Trained classifier checkpoint exists with documented precision/recall/F1 numbers
- [ ] Inference runs inside the gateway pipeline without reloading the model per request
- [ ] The score/action boundary test passes — this is the architectural contract module 6 depends on
- [ ] Output scan catches both leakage types in test
- [ ] All tests pass; `ruff check` clean
