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

1,913 examples after exact-text de-duplication, split ~80/10/10:

| Split | benign | prompt_injection | jailbreak | total |
|---|---|---|---|---|
| train | 799 | 203 | 521 | 1,523 |
| val | 100 | 31 | 65 | 196 |
| test | 100 | 29 | 65 | 194 |

### Near-duplicate-aware split

The jailbreak datasets reuse the same templates with small edits, so exact
de-duplication alone isn't enough. In the first version of this pipeline, a
plain random split left **33 of the 91 attack rows in the test set as
near-copies of training rows** (≥50% of their word 8-grams shared). That
inflated the reported scores: on the leak-free subset, injection F1 was 0.81,
not the 0.87 originally reported.

`prepare_dataset.py` now clusters near-duplicates (union-find over shared
word 8-grams, threshold 0.5) and assigns each whole cluster to a single split.
Re-running the same check on the new split finds **0** test rows with a
near-copy in training. All numbers below are on this leak-free split.

## Training setup

- fp32 throughout; batch 4 × gradient accumulation 4 (effective 16); lr 2e-5;
  10% warmup; max 4 epochs; max sequence length 160; best checkpoint chosen
  by validation macro-F1 (early-stopping patience 2)
- Class-weighted cross-entropy (inverse frequency, square-root dampened:
  benign 0.71, prompt_injection 1.41, jailbreak 0.88), to lift recall on the
  smallest class
- Hardware: RTX 3050 Laptop GPU (4 GB), ~40 min for 4 epochs
- Best checkpoint: epoch 4 (validation macro-F1 0.958)

| Epoch | Val macro-F1 | Val injection F1 |
|---|---|---|
| 1 | 0.901 | 0.793 |
| 2 | 0.945 | 0.893 |
| 3 | 0.944 | 0.893 |
| 4 | **0.958** | 0.915 |

**Pitfall worth knowing:** transformers 5.x's `from_pretrained` loads weights
in the checkpoint's *stored* dtype by default, and `deberta-v3-base` is stored
in fp16. Without `dtype=torch.float32` the model silently trains in pure fp16
with no loss scaling: NaN gradients from step 1, and a model that predicts
`benign` for everything (macro-F1 0.23). Our first runs failed exactly this
way, and switching the `Trainer` precision flags (`fp16`/`bf16`) does not fix
it. All loaders in this repo now pass `dtype=torch.float32` explicitly.

## Results: held-out test set (194 examples, leak-free)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 0.94 | 0.99 | 0.97 | 100 |
| prompt_injection | 0.89 | 0.83 | 0.86 | 29 |
| jailbreak | 1.00 | 0.95 | 0.98 | 65 |
| **macro avg** | **0.94** | **0.92** | **0.93** | 194 |

Accuracy: 0.95.

Confusion matrix (rows = true, columns = predicted):

| | benign | prompt_injection | jailbreak |
|---|---|---|---|
| **benign** | 99 | 1 | 0 |
| **prompt_injection** | 5 | 24 | 0 |
| **jailbreak** | 1 | 2 | 62 |

### Targets (set after the first successful run, per the module plan)

| Metric | Target | Achieved |
|---|---|---|
| prompt_injection F1 | ≥ 0.85 | 0.86 ✅ (narrowly) |
| jailbreak F1 | ≥ 0.90 | 0.98 ✅ |
| macro F1 | ≥ 0.90 | 0.93 ✅ |

Compared like-for-like on leak-free data, the first model reached injection
F1 0.81 (recall 0.69); this one reaches 0.86 (recall 0.83).

### Interpretation and limitations

- **The weak spot is still prompt_injection** (5 of 29 missed). With only 29
  test examples, one miss moves recall by ~3.5 points, so treat these as
  indicative rather than tight estimates.
- **Known false positives** found by hand-probing: "Forget about the budget
  numbers, focus on the timeline" scores 0.98 injection. Imperative
  "forget/ignore X" phrasing in ordinary requests is the main
  false-positive pattern; the class weighting that raised injection recall
  makes it slightly more likely. Two earlier false positives ("Ignore the
  typo in my last message", a story quoting "ignore all rules") now score
  benign.
- Both points are why this module only produces a *score*: module 6's bandit
  decides the action and should treat a lone high injection score on a
  short, otherwise ordinary prompt with some caution rather than
  hard-blocking on argmax.
- The data is public benchmark text, so performance on novel or adaptive
  attacks will be lower. The adversarial red-team loop is tracked separately
  as a stretch goal.

## How the gateway scores a request

- Every message's text is scored, including list-form content
  (`[{"type": "text", ...}]`). Earlier, list-form content skipped the
  classifier entirely.
- Each message is split into overlapping 160-token windows (stride 126), and
  the request's score is the distribution of the most suspicious window.
  Earlier, a single pass truncated at 256 tokens, so ~250 tokens of benign
  padding before an injection dropped its score from 0.995 to 0.003. With
  windowing, the same padded injection scores 0.997.
- At most 32 windows (~4,000 tokens) are scanned per request.
  `ctx.metadata["threat_scan"]["truncated"]` is set when a request exceeds
  that, so module 6 can treat it as suspicious rather than trust an
  incomplete scan.

## Inference latency

Measured on the training laptop, averaged over warm calls:

| Device | Short prompt (1 window) | ~1,000 tokens (6 windows) |
|---|---|---|
| RTX 3050 Laptop GPU | ~20–60 ms | ~90 ms |
| CPU (same laptop) | ~160–230 ms | **~1.5 s** |

Ranges reflect the laptop's power state: the same short prompt measured
21 ms at full GPU clocks and ~60 ms when throttled. Windowing itself adds
about 10% over a single pass for a short prompt.

CPU inference is fine for short prompts in a low-QPS demo, but cost grows
linearly with prompt length: at the 32-window cap, a CPU-only deployment
would spend several seconds per request. Use a GPU (or the optional ONNX
export) for anything beyond a demo, or lower `MAX_WINDOWS` in
`classifier.py` on CPU-only hosts.
