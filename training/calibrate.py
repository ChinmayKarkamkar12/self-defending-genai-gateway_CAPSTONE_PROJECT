"""Fit a temperature for the threat classifier's scores (temperature scaling,
Guo et al. 2017) on validation data, and save it next to the checkpoint.

The fine-tuned classifier is over-confident: almost every score is near 0 or 1
(LIMITATIONS.md L6a-1). Dividing the logits by one fitted number T > 1 softens
the probabilities without changing any argmax prediction, so accuracy and F1
are unchanged while a score of 0.7 comes closer to meaning "70% of such
prompts are attacks". The gateway reads `calibration.json` from the checkpoint
directory (no file = T 1.0, the uncalibrated behaviour).

Only validation data is used to fit T; the test sets are not touched here.

Run from the repo root with the project venv:
    gateway/.venv/Scripts/python.exe training/calibrate.py \
        --checkpoint training/checkpoints/v2/final --val-file training/data/v2/val.jsonl
"""

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("calibrate")

MAX_LENGTH = 160
N_BINS = 10


def load_rows(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def compute_logits(checkpoint: Path, texts: list[str], batch_size: int = 16) -> np.ndarray:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint, dtype=torch.float32)
    model.to(device).eval()
    out = []
    with torch.inference_mode():
        for i in range(0, len(texts), batch_size):
            inputs = tokenizer(
                texts[i : i + batch_size],
                return_tensors="pt",
                truncation=True,
                max_length=MAX_LENGTH,
                padding=True,
            ).to(device)
            out.append(model(**inputs).logits.float().cpu().numpy())
    return np.concatenate(out)


def softmax(logits: np.ndarray, temperature: float) -> np.ndarray:
    z = logits / temperature
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def nll(logits: np.ndarray, labels: np.ndarray, temperature: float) -> float:
    probs = softmax(logits, temperature)
    return float(-np.log(np.clip(probs[np.arange(len(labels)), labels], 1e-12, None)).mean())


def attack_ece(logits: np.ndarray, labels: np.ndarray, temperature: float) -> float:
    """Expected calibration error of the gateway's actual score, the attack
    probability 1 - P(benign), against "is an attack" (equal-width bins)."""
    attack_prob = 1.0 - softmax(logits, temperature)[:, 0]
    is_attack = (labels != 0).astype(float)
    bins = np.minimum((attack_prob * N_BINS).astype(int), N_BINS - 1)
    ece = 0.0
    for b in range(N_BINS):
        mask = bins == b
        if mask.any():
            ece += mask.mean() * abs(attack_prob[mask].mean() - is_attack[mask].mean())
    return float(ece)


def fit_temperature(logits: np.ndarray, labels: np.ndarray) -> float:
    """Minimise validation NLL over T: a log-spaced grid, then a finer grid
    around the best point (one parameter, so a grid is exact enough)."""
    grid = np.exp(np.linspace(np.log(0.25), np.log(20.0), 200))
    best = min(grid, key=lambda t: nll(logits, labels, t))
    fine = np.linspace(best * 0.9, best * 1.1, 200)
    return float(min(fine, key=lambda t: nll(logits, labels, t)))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--val-file", type=Path, required=True)
    cli = parser.parse_args()

    rows = load_rows(cli.val_file)
    labels = np.array([r["label"] for r in rows])
    logits = compute_logits(cli.checkpoint, [r["text"] for r in rows])

    temperature = fit_temperature(logits, labels)
    result = {
        "temperature": round(temperature, 4),
        "fitted_on": str(cli.val_file),
        "val_size": len(rows),
        "val_nll": {"before": nll(logits, labels, 1.0), "after": nll(logits, labels, temperature)},
        "val_attack_ece": {
            "before": attack_ece(logits, labels, 1.0),
            "after": attack_ece(logits, labels, temperature),
        },
    }
    (cli.checkpoint / "calibration.json").write_text(json.dumps(result, indent=2))
    logger.info("calibration: %s", json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
