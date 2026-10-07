"""Pull and merge public datasets into a 3-class train/val/test split for
the threat classifier. See project_plan/05-threat-detection-classifier.md §2.

Sources:
  - deepset/prompt-injections  (text, label 0/1)        -> benign / prompt_injection
  - jackhhao/jailbreak-classification (prompt, type)      -> benign / jailbreak
  - tatsu-lab/alpaca (instruction)                        -> benign (extra negatives,
    so the classifier doesn't learn "any unusual phrasing = attack" from the
    attack datasets' own benign examples alone)

Labels: 0=benign, 1=prompt_injection, 2=jailbreak.

Run from the repo root with the project venv:
    gateway/.venv/Scripts/python.exe training/prepare_dataset.py

Writes train.jsonl / val.jsonl / test.jsonl / stats.json to training/data/.
"""

import json
import logging
import random
from pathlib import Path

from datasets import load_dataset

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("prepare_dataset")

SEED = 42
DATA_DIR = Path(__file__).resolve().parent / "data"

LABEL_BENIGN, LABEL_INJECTION, LABEL_JAILBREAK = 0, 1, 2
LABEL_NAMES = {
    LABEL_BENIGN: "benign",
    LABEL_INJECTION: "prompt_injection",
    LABEL_JAILBREAK: "jailbreak",
}

# How many alpaca instructions to pull in as extra benign negatives. Capped
# deliberately - alpaca alone has 52k rows, and we don't want benign to
# swamp the two attack classes (each a few hundred examples) by orders of
# magnitude. See the benign-capping step below for the final balancing pass.
ALPACA_SAMPLE_SIZE = 900


def _dedupe(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for row in rows:
        key = row["text"].strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def load_prompt_injections() -> tuple[list[dict], list[dict]]:
    injection_rows, benign_rows = [], []
    ds = load_dataset("deepset/prompt-injections")
    for split in ("train", "test"):
        for row in ds[split]:
            text = row["text"]
            if row["label"] == 1:
                injection_rows.append({"text": text, "label": LABEL_INJECTION})
            else:
                benign_rows.append({"text": text, "label": LABEL_BENIGN})
    logger.info(
        "deepset/prompt-injections: %d injection, %d benign", len(injection_rows), len(benign_rows)
    )
    return injection_rows, benign_rows


def load_jailbreak_classification() -> tuple[list[dict], list[dict]]:
    jailbreak_rows, benign_rows = [], []
    ds = load_dataset("jackhhao/jailbreak-classification")
    for split in ("train", "test"):
        for row in ds[split]:
            text = row["prompt"]
            if row["type"] == "jailbreak":
                jailbreak_rows.append({"text": text, "label": LABEL_JAILBREAK})
            else:
                benign_rows.append({"text": text, "label": LABEL_BENIGN})
    logger.info(
        "jackhhao/jailbreak-classification: %d jailbreak, %d benign",
        len(jailbreak_rows),
        len(benign_rows),
    )
    return jailbreak_rows, benign_rows


def load_alpaca_benign(rng: random.Random, sample_size: int) -> list[dict]:
    ds = load_dataset("tatsu-lab/alpaca")["train"]
    indices = rng.sample(range(len(ds)), min(sample_size, len(ds)))
    rows = [{"text": ds[i]["instruction"], "label": LABEL_BENIGN} for i in indices]
    logger.info("tatsu-lab/alpaca: sampled %d benign", len(rows))
    return rows


def stratified_split(
    rows: list[dict], rng: random.Random, val_frac: float = 0.1, test_frac: float = 0.1
):
    by_label: dict[int, list[dict]] = {}
    for row in rows:
        by_label.setdefault(row["label"], []).append(row)

    train, val, test = [], [], []
    for group in by_label.values():
        rng.shuffle(group)
        n = len(group)
        n_val = max(1, int(n * val_frac))
        n_test = max(1, int(n * test_frac))
        val.extend(group[:n_val])
        test.extend(group[n_val : n_val + n_test])
        train.extend(group[n_val + n_test :])
    rng.shuffle(train)
    rng.shuffle(val)
    rng.shuffle(test)
    return train, val, test


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def main() -> None:
    rng = random.Random(SEED)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    injection_rows, benign_from_injections = load_prompt_injections()
    jailbreak_rows, benign_from_jailbreak = load_jailbreak_classification()

    # Target benign count: large enough to be a real negative class, but
    # capped relative to the two attack classes so training data isn't
    # ~98% benign (alpaca alone is 52k rows). Picked as ~1.5x the larger
    # attack class, with a floor so small attack-class counts don't starve
    # benign entirely.
    attack_class_size = max(len(injection_rows), len(jailbreak_rows))
    benign_target = max(int(attack_class_size * 1.5), 600)

    benign_pool = _dedupe(benign_from_injections + benign_from_jailbreak)
    if len(benign_pool) < benign_target:
        benign_pool += load_alpaca_benign(rng, benign_target - len(benign_pool) + 200)
    benign_pool = _dedupe(benign_pool)
    rng.shuffle(benign_pool)
    benign_rows = benign_pool[:benign_target]

    all_rows = _dedupe(injection_rows + jailbreak_rows + benign_rows)
    train, val, test = stratified_split(all_rows, rng)

    write_jsonl(DATA_DIR / "train.jsonl", train)
    write_jsonl(DATA_DIR / "val.jsonl", val)
    write_jsonl(DATA_DIR / "test.jsonl", test)

    def counts(rows: list[dict]) -> dict[str, int]:
        c = {name: 0 for name in LABEL_NAMES.values()}
        for row in rows:
            c[LABEL_NAMES[row["label"]]] += 1
        return c

    stats = {
        "seed": SEED,
        "total": len(all_rows),
        "train": {"size": len(train), "counts": counts(train)},
        "val": {"size": len(val), "counts": counts(val)},
        "test": {"size": len(test), "counts": counts(test)},
    }
    (DATA_DIR / "stats.json").write_text(json.dumps(stats, indent=2))
    logger.info("wrote train/val/test to %s", DATA_DIR)
    logger.info("stats: %s", json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
