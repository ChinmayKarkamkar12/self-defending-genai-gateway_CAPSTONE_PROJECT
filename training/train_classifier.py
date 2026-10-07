"""Fine-tune microsoft/deberta-v3-base on the 3-class threat task (benign /
prompt_injection / jailbreak). See project_plan/05-threat-detection-classifier.md §2.

Run from the repo root with the project venv, after prepare_dataset.py:
    gateway/.venv/Scripts/python.exe training/train_classifier.py

Saves the best checkpoint (by validation macro-F1) to
training/checkpoints/final/, ready for app/core/threat/classifier.py to load.

Sized for a 4GB-VRAM laptop GPU (RTX 3050): fp16, small per-device batch
size with gradient accumulation to reach a reasonable effective batch size,
short max sequence length (these are prompts, not documents). Falls back to
CPU automatically if no CUDA device is available - just slower.
"""

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
FINAL_DIR = OUTPUT_DIR / "final"
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


def main() -> None:
    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("training on device: %s", device)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=MAX_LENGTH)

    train_ds = load_jsonl(DATA_DIR / "train.jsonl").map(tokenize, batched=True)
    val_ds = load_jsonl(DATA_DIR / "val.jsonl").map(tokenize, batched=True)

    # dtype=torch.float32 is load-bearing, not cosmetic. transformers 5.x's
    # from_pretrained defaults to the checkpoint's *stored* dtype, and
    # deberta-v3-base's safetensors are stored in fp16 - so without this the
    # model silently trains in pure fp16 with no loss scaling, which is what
    # produced NaN grad_norm from step 1 (and the "Attempting to unscale
    # FP16 gradients" error when fp16=True was tried) in earlier runs.
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(LABEL_NAMES),
        id2label=dict(enumerate(LABEL_NAMES)),
        dtype=torch.float32,
    )

    collator = DataCollatorWithPadding(tokenizer=tokenizer)

    per_device_train_batch_size = 8
    gradient_accumulation_steps = 2  # effective batch size 16
    num_train_epochs = 4
    effective_batch_size = per_device_train_batch_size * gradient_accumulation_steps
    steps_per_epoch = max(1, len(train_ds) // effective_batch_size)
    # This transformers version's TrainingArguments only accepts
    # `warmup_steps`, not the more convenient `warmup_ratio` - compute the
    # equivalent of a 10% warmup fraction by hand.
    warmup_steps = max(1, int(steps_per_epoch * num_train_epochs * 0.1))

    args = TrainingArguments(
        output_dir=str(OUTPUT_DIR / "run"),
        per_device_train_batch_size=per_device_train_batch_size,
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=gradient_accumulation_steps,
        num_train_epochs=num_train_epochs,
        learning_rate=2e-5,
        weight_decay=0.01,
        warmup_steps=warmup_steps,
        # No mixed precision, deliberately: full fp32 (weights forced to
        # fp32 at load time above) fits in 4GB VRAM at this batch
        # size/sequence length, and DeBERTa-v3 is known to be finicky under
        # reduced precision - not worth the risk for a ~2 minute/epoch job.
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        logging_steps=25,
        report_to=[],
        seed=42,
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=collator,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    trainer.train()

    FINAL_DIR.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(FINAL_DIR))
    tokenizer.save_pretrained(str(FINAL_DIR))
    logger.info("saved best checkpoint to %s", FINAL_DIR)

    val_metrics = trainer.evaluate()
    logger.info("final validation metrics: %s", json.dumps(val_metrics, indent=2))
    (OUTPUT_DIR / "val_metrics.json").write_text(json.dumps(val_metrics, indent=2))


if __name__ == "__main__":
    main()
