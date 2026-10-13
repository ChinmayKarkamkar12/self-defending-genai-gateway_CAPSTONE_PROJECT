"""Fine-tune microsoft/deberta-v3-base on the 3-class threat task (benign /
prompt_injection / jailbreak). See project_plan/05-threat-detection-classifier.md §2.

Run from the repo root with the project venv, after prepare_dataset.py:
    gateway/.venv/Scripts/python.exe training/train_classifier.py

v2 (data expansion, see training/README.md):
    gateway/.venv/Scripts/python.exe training/train_classifier.py
        --data-dir training/data/v2 --output-dir training/checkpoints/v2

Saves the best checkpoint (by validation macro-F1) to
training/checkpoints/final/, ready for app/core/threat/classifier.py to load.

v3 (data expansion, second attempt, see training/README.md "Classifier v3"):
    gateway/.venv/Scripts/python.exe training/train_classifier.py
        --data-dir training/data/v2 --output-dir training/checkpoints/v3
        --init-from training/checkpoints/final --oversample-v1 2
        --learning-rate 1e-5 --epochs 2 --v1-floor 0.947

Sized for a 4GB-VRAM laptop GPU (RTX 3050): fp16, small per-device batch
size with gradient accumulation to reach a reasonable effective batch size,
short max sequence length (these are prompts, not documents). Falls back to
CPU automatically if no CUDA device is available - just slower.
"""

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import f1_score, precision_recall_fscore_support
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("train_classifier")

MODEL_NAME = "microsoft/deberta-v3-base"
DATA_DIR = Path(__file__).resolve().parent / "data"
OUTPUT_DIR = Path(__file__).resolve().parent / "checkpoints"
MAX_LENGTH = 160
LABEL_NAMES = ["benign", "prompt_injection", "jailbreak"]


def load_jsonl(path: Path) -> Dataset:
    rows = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    return Dataset.from_list(rows)


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, labels=list(range(len(LABEL_NAMES))), zero_division=0
    )
    macro_f1 = f1_score(labels, preds, average="macro", zero_division=0)
    metrics = {"macro_f1": macro_f1}
    for i, name in enumerate(LABEL_NAMES):
        metrics[f"precision_{name}"] = precision[i]
        metrics[f"recall_{name}"] = recall[i]
        metrics[f"f1_{name}"] = f1[i]
    return metrics


def make_compute_metrics(val_is_v1: np.ndarray | None, v1_floor: float | None):
    """compute_metrics, plus (for v3) macro-F1 on the v1-origin and new-origin
    validation rows and a `select` metric used to pick the best epoch: the
    new-origin macro-F1 if the v1-origin macro-F1 stays at or above
    `v1_floor`, otherwise that minus 1 (so any epoch meeting the floor wins)."""

    def compute(eval_pred):
        metrics = compute_metrics(eval_pred)
        if val_is_v1 is None:
            return metrics
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        parts = {"v1part": val_is_v1, "newpart": ~val_is_v1}
        for name, mask in parts.items():
            metrics[f"macro_f1_{name}"] = f1_score(
                labels[mask], preds[mask], average="macro", zero_division=0
            )
        penalty = 0.0 if metrics["macro_f1_v1part"] >= v1_floor else 1.0
        metrics["select"] = metrics["macro_f1_newpart"] - penalty
        return metrics

    return compute


def class_weights(labels: list[int]) -> torch.Tensor:
    """Inverse-frequency weights, square-root dampened, normalized to mean 1.

    prompt_injection is the smallest class (~200 training rows vs ~800
    benign) and was the weakest on recall in the first run. Full inverse
    frequency over-corrects into benign false positives; sqrt is the usual
    middle ground.
    """
    counts = np.bincount(labels, minlength=len(LABEL_NAMES)).astype(np.float64)
    weights = 1.0 / np.sqrt(counts)
    weights = weights / weights.mean()
    return torch.tensor(weights, dtype=torch.float32)


class WeightedLossTrainer(Trainer):
    def __init__(self, *args, loss_weights: torch.Tensor, **kwargs):
        super().__init__(*args, **kwargs)
        self._loss_weights = loss_weights

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        loss_fn = torch.nn.CrossEntropyLoss(weight=self._loss_weights.to(outputs.logits.device))
        loss = loss_fn(outputs.logits, labels)
        return (loss, outputs) if return_outputs else loss


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    # Continue an interrupted run from a saved epoch checkpoint (restores the
    # optimizer, scheduler and RNG state, so the result matches an unbroken run).
    parser.add_argument("--resume-from", type=Path, default=None)
    # v3: start from an already fine-tuned checkpoint instead of the base model,
    # repeat the v1-origin training rows (no `source` field) N times in total,
    # and pick the best epoch by the `select` metric (see make_compute_metrics).
    parser.add_argument("--init-from", type=Path, default=None)
    parser.add_argument("--oversample-v1", type=int, default=1)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--v1-floor", type=float, default=None)
    # Save only model weights each epoch (no ~1.5 GB optimizer state): writing
    # the optimizer state spiked RAM enough to get the run killed on the
    # laptop. A run saved this way can't be resumed with --resume-from.
    parser.add_argument("--save-only-model", action="store_true")
    cli = parser.parse_args()
    data_dir, output_dir = cli.data_dir, cli.output_dir
    final_dir = output_dir / "final"

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("training on device: %s", device)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=MAX_LENGTH)

    train_rows = [
        json.loads(line)
        for line in (data_dir / "train.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if cli.oversample_v1 > 1:
        v1_rows = [r for r in train_rows if r.get("source") is None]
        train_rows += v1_rows * (cli.oversample_v1 - 1)
        logger.info("v1-origin rows x%d: %d training rows", cli.oversample_v1, len(train_rows))
    train_ds = Dataset.from_list(train_rows).map(tokenize, batched=True)
    val_ds = load_jsonl(data_dir / "val.jsonl").map(tokenize, batched=True)
    val_is_v1 = None
    if cli.v1_floor is not None:
        val_is_v1 = np.array([s is None for s in val_ds["source"]])

    # dtype=torch.float32 is load-bearing, not cosmetic. transformers 5.x's
    # from_pretrained defaults to the checkpoint's *stored* dtype, and
    # deberta-v3-base's safetensors are stored in fp16 - so without this the
    # model silently trains in pure fp16 with no loss scaling, which is what
    # produced NaN grad_norm from step 1 (and the "Attempting to unscale
    # FP16 gradients" error when fp16=True was tried) in earlier runs.
    model = AutoModelForSequenceClassification.from_pretrained(
        str(cli.init_from) if cli.init_from else MODEL_NAME,
        num_labels=len(LABEL_NAMES),
        id2label=dict(enumerate(LABEL_NAMES)),
        dtype=torch.float32,
    )

    collator = DataCollatorWithPadding(tokenizer=tokenizer)

    # 4 x 4 rather than 8 x 2: same effective batch of 16, but the 8-wide
    # batch nearly filled the 4GB RTX 3050 and later epochs slowed ~20x as
    # memory spilled into shared system RAM.
    per_device_train_batch_size = 4
    gradient_accumulation_steps = 4
    num_train_epochs = cli.epochs
    effective_batch_size = per_device_train_batch_size * gradient_accumulation_steps
    steps_per_epoch = max(1, len(train_ds) // effective_batch_size)
    # This transformers version's TrainingArguments only accepts
    # `warmup_steps`, not the more convenient `warmup_ratio` - compute the
    # equivalent of a 10% warmup fraction by hand.
    warmup_steps = max(1, int(steps_per_epoch * num_train_epochs * 0.1))

    args = TrainingArguments(
        output_dir=str(output_dir / "run"),
        per_device_train_batch_size=per_device_train_batch_size,
        per_device_eval_batch_size=8,
        gradient_accumulation_steps=gradient_accumulation_steps,
        num_train_epochs=num_train_epochs,
        learning_rate=cli.learning_rate,
        weight_decay=0.01,
        warmup_steps=warmup_steps,
        # No mixed precision, deliberately: full fp32 (weights forced to
        # fp32 at load time above) fits in 4GB VRAM at this batch
        # size/sequence length, and DeBERTa-v3 is known to be finicky under
        # reduced precision - not worth the risk for a ~2 minute/epoch job.
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        save_only_model=cli.save_only_model,
        load_best_model_at_end=True,
        metric_for_best_model="select" if cli.v1_floor is not None else "macro_f1",
        greater_is_better=True,
        logging_steps=25,
        report_to=[],
        seed=42,
    )

    loss_weights = class_weights(train_ds["label"])
    logger.info("class loss weights %s: %s", LABEL_NAMES, loss_weights.tolist())

    trainer = WeightedLossTrainer(
        loss_weights=loss_weights,
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=collator,
        compute_metrics=make_compute_metrics(val_is_v1, cli.v1_floor),
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    trainer.train(resume_from_checkpoint=str(cli.resume_from) if cli.resume_from else None)

    final_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))
    logger.info("saved best checkpoint to %s", final_dir)

    val_metrics = trainer.evaluate()
    logger.info("final validation metrics: %s", json.dumps(val_metrics, indent=2))
    (output_dir / "val_metrics.json").write_text(json.dumps(val_metrics, indent=2))


if __name__ == "__main__":
    main()
