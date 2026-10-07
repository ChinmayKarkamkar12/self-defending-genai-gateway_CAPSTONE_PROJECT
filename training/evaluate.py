"""Evaluate the trained checkpoint on the held-out test split and report
precision/recall/F1 per class. See project_plan/05-threat-detection-classifier.md §5-6.

Run from the repo root with the project venv, after train_classifier.py:
    gateway/.venv/Scripts/python.exe training/evaluate.py

Writes training/checkpoints/test_metrics.json and prints a report - these
numbers go into the module's README (project requirement, not optional).
"""

import json
import logging
from pathlib import Path

import torch
from datasets import Dataset
from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("evaluate")

DATA_DIR = Path(__file__).resolve().parent / "data"
CHECKPOINT_DIR = Path(__file__).resolve().parent / "checkpoints" / "final"
OUTPUT_PATH = Path(__file__).resolve().parent / "checkpoints" / "test_metrics.json"
MAX_LENGTH = 160
LABEL_NAMES = ["benign", "prompt_injection", "jailbreak"]


def load_jsonl(path: Path) -> Dataset:
    rows = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    return Dataset.from_list(rows)


def main() -> None:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(CHECKPOINT_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(
        CHECKPOINT_DIR, dtype=torch.float32
    ).to(device)
    model.eval()

    test_ds = load_jsonl(DATA_DIR / "test.jsonl")

    all_preds, all_labels = [], []
    batch_size = 16
    texts = test_ds["text"]
    labels = test_ds["label"]

    with torch.inference_mode():
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i : i + batch_size]
            inputs = tokenizer(
                batch_texts,
                return_tensors="pt",
                truncation=True,
                max_length=MAX_LENGTH,
                padding=True,
            ).to(device)
            logits = model(**inputs).logits
            preds = torch.argmax(logits, dim=-1).cpu().tolist()
            all_preds.extend(preds)
            all_labels.extend(labels[i : i + batch_size])

    report = classification_report(
        all_labels,
        all_preds,
        labels=list(range(len(LABEL_NAMES))),
        target_names=LABEL_NAMES,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(all_labels, all_preds, labels=list(range(len(LABEL_NAMES))))

    result = {
        "report": report,
        "confusion_matrix": cm.tolist(),
        "label_order": LABEL_NAMES,
        "test_set_size": len(all_labels),
    }
    OUTPUT_PATH.write_text(json.dumps(result, indent=2))

    logger.info("test set size: %d", len(all_labels))
    logger.info(
        "\n%s",
        classification_report(
            all_labels,
            all_preds,
            labels=list(range(len(LABEL_NAMES))),
            target_names=LABEL_NAMES,
            zero_division=0,
        ),
    )
    logger.info("confusion matrix (rows=true, cols=pred), order %s:\n%s", LABEL_NAMES, cm)
    logger.info("wrote %s", OUTPUT_PATH)


if __name__ == "__main__":
    main()
