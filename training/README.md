# Threat classifier training (Module 5)

Offline fine-tuning of `microsoft/deberta-v3-base` as a 3-class classifier
(`benign` / `prompt_injection` / `jailbreak`). The gateway loads the result from
`training/checkpoints/final/` (see `gateway/app/core/threat/classifier.py`).

## Reproduce

From the repo root, using the project venv:

```bash
gateway/.venv/Scripts/python.exe -m pip install -r gateway/requirements.txt
gateway/.venv/Scripts/python.exe -m pip install -r training/requirements.txt
gateway/.venv/Scripts/python.exe training/prepare_dataset.py   # -> training/data/
gateway/.venv/Scripts/python.exe training/train_classifier.py  # -> training/checkpoints/final/
gateway/.venv/Scripts/python.exe training/evaluate.py          # -> training/checkpoints/test_metrics.json
```

`training/data/` and `training/checkpoints/` are git-ignored; both are fully
reproducible from the commands above (seed 42).

For GPU training, install a CUDA build of torch rather than the plain PyPI
wheel (this run used `torch 2.6.0+cu124`, `transformers 5.19.0`).

## Data

| Source | Used for |
|---|---|
| `deepset/prompt-injections` | prompt_injection + benign |
| `jackhhao/jailbreak-classification` | jailbreak + benign |
| `tatsu-lab/alpaca` (sampled) | extra benign instructions, so ordinary prompts aren't mistaken for attacks |

1,913 examples total, stratified 80/10/10:

| Split | benign | prompt_injection | jailbreak | total |
|---|---|---|---|---|
| train | 801 | 211 | 521 | 1,533 |
| val | 99 | 26 | 65 | 190 |
| test | 99 | 26 | 65 | 190 |

## Training setup

- fp32 throughout, batch 8 × grad-accumulation 2 (effective 16), lr 2e-5,
  10% warmup, max 4 epochs, max sequence length 160, early stopping on
  validation macro-F1 (patience 2)
- Hardware: RTX 3050 Laptop GPU (4 GB). About 45 min for 4 epochs; the run
  nearly fills VRAM, so later epochs slow down as memory spills to shared RAM.
- Best checkpoint: epoch 3 (validation macro-F1 0.935)

| Epoch | Validation macro-F1 |
|---|---|
| 1 | 0.843 |
| 2 | 0.920 |
| 3 | **0.935** |
| 4 | 0.934 |

**Pitfall worth knowing:** transformers 5.x's `from_pretrained` loads weights
in the checkpoint's *stored* dtype by default, and `deberta-v3-base` is stored
in fp16. Without `dtype=torch.float32` the model silently trains in pure fp16
with no loss scaling: NaN gradients from step 1, and a model that predicts
`benign` for everything (macro-F1 0.23). Our first runs failed exactly this
way, and switching the `Trainer` precision flags (`fp16`/`bf16`) does not fix
it. All loaders in this repo now pass `dtype=torch.float32` explicitly.

## Results: held-out test set (190 examples)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 0.93 | 1.00 | 0.96 | 99 |
| prompt_injection | 1.00 | 0.77 | 0.87 | 26 |
| jailbreak | 0.97 | 0.94 | 0.95 | 65 |
| **macro avg** | **0.96** | **0.90** | **0.93** | 190 |

Accuracy: 0.95.

Confusion matrix (rows = true, columns = predicted):

| | benign | prompt_injection | jailbreak |
|---|---|---|---|
| **benign** | 99 | 0 | 0 |
| **prompt_injection** | 4 | 20 | 2 |
| **jailbreak** | 4 | 0 | 61 |

### Targets (set after the first successful run, per the module plan)

| Metric | Target | Achieved |
|---|---|---|
| prompt_injection F1 | ≥ 0.85 | 0.87 ✅ |
| jailbreak F1 | ≥ 0.90 | 0.95 ✅ |
| macro F1 | ≥ 0.90 | 0.93 ✅ |

### Interpretation and limitations

- **No false positives on benign traffic** (99/99): the classifier never
  flagged an ordinary prompt as an attack in this test set.
- **The weak spot is prompt_injection recall (0.77).** 4 of 26 injections were
  scored as benign. This is the smallest class (211 training examples), and
  its test support is only 26, so each miss moves recall by about 4 points.
  Treat these numbers as indicative, not tight estimates.
- This is the reason the classifier only produces a *score*: module 6's
  bandit decides the action and can be tuned to escalate on moderate
  injection probabilities, rather than relying on an argmax label.
- The data is public benchmark text, so performance on novel or adaptive
  attacks will be lower. The adversarial red-team loop is tracked separately
  as a stretch goal.

## Inference latency

Single prompt, after warm-up, averaged over 20 calls (~40 tokens):

| Device | Latency |
|---|---|
| RTX 3050 Laptop GPU | ~21 ms |
| CPU (same laptop) | ~161 ms |

CPU inference is fine for a low-QPS demo deployment, but it adds about 160 ms
to every request. Plan for a GPU (or the optional ONNX export) before
assuming production-like latency.
