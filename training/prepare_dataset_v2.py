"""Build the v2 classifier dataset: the v1 data plus new public sources, with a
fresh, locked test split. See training/README.md ("Data expansion (v2)").

v1 (training/data/{train,val,test}.jsonl, from prepare_dataset.py) is kept
unchanged: v2 train = v1 train + new train, v2 val = v1 val + new val, and the
v1 test set stays the "old test" for before/after comparisons. The new test
split contains only new rows and is locked: its SHA-256 goes into stats.json
and it isn't looked at until the final evaluation.

New sources (licence in brackets; all checked on the dataset cards):
  - neuralchemy/Prompt-injection-dataset, core config (Apache-2.0): neuralchemy's
    own rows plus HackAPrompt competition submissions and WildGuard jailbreaks.
    HarmBench rows are dropped (plain harmful requests, not injections), and so
    is the "control" category (harmless text in leetspeak, labelled malicious).
  - TrustAIRLab/in-the-wild-jailbreak-prompts (MIT): the jailbreak prompts as
    jailbreak; the "regular" prompts (same communities, judged not to be
    jailbreaks - mostly "act as X" templates) as hard benign negatives.
  - leolee99/NotInject (MIT): benign prompts full of trigger words, built to
    measure over-defence. English subsets only.
  - databricks/databricks-dolly-15k (CC-BY-SA-3.0): ordinary instructions.
Not used: SPML (its injection label means "off-topic for the chatbot", e.g.
movie recommendations), xTRam1/safe-guard and rubend18 (no licence), and
Lakera Mosscap (unlabelled).

Leakage control: every row, old and new, is clustered with prepare_dataset.py's
near-duplicate union-find. New rows in a cluster that touches the v1 val/test
sets are dropped; new rows in a cluster with v1 train rows can only go to
train; at most MAX_PER_CLUSTER new rows are kept per cluster (template floods
such as DAN variants or "I have been PWNED"); the remaining clusters are split
whole.

Run from the repo root with the project venv:
    gateway/.venv/Scripts/python.exe training/prepare_dataset_v2.py
"""

import hashlib
import json
import logging
import random
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_dataset import (
    LABEL_BENIGN,
    LABEL_INJECTION,
    LABEL_JAILBREAK,
    LABEL_NAMES,
    grouped_stratified_split,
    near_duplicate_groups,
    write_jsonl,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("prepare_dataset_v2")

SEED = 42
DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_DIR = DATA_DIR / "raw_v2"
OUT_DIR = DATA_DIR / "v2"

VAL_FRAC = 0.10
TEST_FRAC = 0.15
MAX_PER_CLUSTER = 3
MIN_CHARS = 10
MAX_CHARS = 10_000

# Caps per source, applied after cleaning (rows are sampled at random).
SOURCE_CAPS = {
    "hackaprompt": 800,
    "neuralchemy_benign": 600,
    "dolly": 1500,
    "itw_regular": 1500,
}

PARQUET_URL = "https://huggingface.co/datasets/{}/resolve/refs%2Fconvert%2Fparquet/{}/0000.parquet"
RAW_FILES = {
    "neural_core_train.parquet": ("neuralchemy/Prompt-injection-dataset", "core/train"),
    "neural_core_val.parquet": (
        "neuralchemy/Prompt-injection-dataset",
        "core/validation",
    ),
    "neural_core_test.parquet": ("neuralchemy/Prompt-injection-dataset", "core/test"),
    "itw_jb_1225.parquet": (
        "TrustAIRLab/in-the-wild-jailbreak-prompts",
        "jailbreak_2023_12_25/train",
    ),
    "itw_reg_1225.parquet": (
        "TrustAIRLab/in-the-wild-jailbreak-prompts",
        "regular_2023_12_25/train",
    ),
    "notinject_1.parquet": ("leolee99/NotInject", "default/NotInject_one"),
    "notinject_2.parquet": ("leolee99/NotInject", "default/NotInject_two"),
    "notinject_3.parquet": ("leolee99/NotInject", "default/NotInject_three"),
    "dolly.parquet": ("databricks/databricks-dolly-15k", "default/train"),
}

# neuralchemy label-1 categories that are jailbreaks (persona / no-rules / multi-turn
# coercion); every other attack category is an injection. The gateway's threat score
# is 1 - P(benign), so this split only matters for per-class metrics.
NEURAL_JAILBREAK_CATEGORIES = {
    "jailbreak",
    "persona_replacement",
    "crescendo",
    "many_shot",
}
NEURAL_DROP_SOURCES = {"harmbench", "harmbench_benign"}
NEURAL_DROP_CATEGORIES = {"control"}

STOPWORDS = {
    "the", "and", "to", "you", "a", "of", "is", "in", "for", "i", "it", "that", "on",
    "with", "as", "your", "be", "are", "this", "me", "my", "what", "how", "can", "will",
}  # fmt: skip


def download_raw() -> dict[str, str]:
    """Fetch the parquet exports (skipping files already present) and return
    their SHA-256 digests, recorded in stats.json for provenance."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    digests = {}
    for name, (repo, path) in RAW_FILES.items():
        dst = RAW_DIR / name
        if not dst.exists():
            logger.info("downloading %s %s", repo, path)
            urllib.request.urlretrieve(PARQUET_URL.format(repo, path), dst)
        digests[name] = hashlib.sha256(dst.read_bytes()).hexdigest()
    return digests


def is_english(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    if not letters or sum(c.isascii() for c in letters) / len(letters) < 0.95:
        return False
    words = re.findall(r"[a-z']+", text.lower())
    return len(set(words) & STOPWORDS) >= (1 if len(words) < 8 else 2)


def _row(text: str, label: int, source: str) -> dict:
    return {"text": text.strip(), "label": label, "source": source}


def load_neuralchemy() -> list[dict]:
    df = pd.concat(
        [pd.read_parquet(RAW_DIR / f"neural_core_{s}.parquet") for s in ("train", "val", "test")]
    )
    df = df[~df.source.isin(NEURAL_DROP_SOURCES) & ~df.category.isin(NEURAL_DROP_CATEGORIES)]
    rows = []
    for r in df.itertuples():
        if r.label == 0:
            label, source = LABEL_BENIGN, "neuralchemy_benign"
        elif r.category in NEURAL_JAILBREAK_CATEGORIES or r.source == "wildguard_judgecomp":
            label, source = LABEL_JAILBREAK, f"neuralchemy_{r.source}"
        else:
            label, source = LABEL_INJECTION, f"neuralchemy_{r.source}"
        if r.source == "hackaprompt":
            source = "hackaprompt"
        rows.append(_row(r.text, label, source))
    return rows


def load_in_the_wild() -> list[dict]:
    jb = pd.read_parquet(RAW_DIR / "itw_jb_1225.parquet")
    reg = pd.read_parquet(RAW_DIR / "itw_reg_1225.parquet")
    rows = [_row(t, LABEL_JAILBREAK, "itw_jailbreak") for t in jb.prompt]
    rows += [_row(t, LABEL_BENIGN, "itw_regular") for t in reg.prompt if is_english(t)]
    return rows


def load_notinject() -> list[dict]:
    df = pd.concat([pd.read_parquet(RAW_DIR / f"notinject_{i}.parquet") for i in (1, 2, 3)])
    return [_row(t, LABEL_BENIGN, "notinject") for t in df[df.category != "Multilingual"].prompt]


def load_dolly() -> list[dict]:
    df = pd.read_parquet(RAW_DIR / "dolly.parquet")
    return [_row(t, LABEL_BENIGN, "dolly") for t in df.instruction]


def load_v1() -> dict[str, list[dict]]:
    out = {}
    for split in ("train", "val", "test"):
        lines = (DATA_DIR / f"{split}.jsonl").read_text(encoding="utf-8").splitlines()
        out[split] = [json.loads(line) for line in lines if line.strip()]
    return out


def _norm(text: str) -> str:
    return " ".join(re.sub(r"\W+", " ", text.lower()).split())


def clean_and_cap(rows: list[dict], v1_texts: set[str], rng: random.Random) -> list[dict]:
    """Length filter, exact (normalised) dedupe within the new data and against
    v1, drop texts that appear with conflicting labels, then per-source caps."""
    by_text: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if MIN_CHARS <= len(row["text"]) <= MAX_CHARS:
            by_text[_norm(row["text"])].append(row)
    kept = []
    conflicts = 0
    for key, group in by_text.items():
        if not key or key in v1_texts:
            continue
        if len({r["label"] for r in group}) > 1:
            conflicts += 1
            continue
        kept.append(group[0])
    logger.info("dropped %d texts with conflicting labels across sources", conflicts)

    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in kept:
        by_source[row["source"]].append(row)
    out = []
    for source, group in sorted(by_source.items()):
        rng.shuffle(group)
        cap = SOURCE_CAPS.get(source)
        out.extend(group[:cap] if cap else group)
    return out


def main() -> None:
    rng = random.Random(SEED)
    digests = download_raw()
    v1 = load_v1()
    for split, rows in v1.items():
        for row in rows:
            row["v1_split"] = split

    raw = load_neuralchemy() + load_in_the_wild() + load_notinject() + load_dolly()
    logger.info("raw candidate rows: %d", len(raw))
    v1_texts = {_norm(r["text"]) for rows in v1.values() for r in rows}
    new_rows = clean_and_cap(raw, v1_texts, rng)
    logger.info("after cleaning and caps: %d", len(new_rows))

    # Cluster old and new together so near-copies of v1 rows are caught.
    v1_all = v1["train"] + v1["val"] + v1["test"]
    forced_train, free, dropped_heldout, dropped_cap = [], [], 0, 0
    for group in near_duplicate_groups(v1_all + new_rows):
        old_splits = {r["v1_split"] for r in group if "v1_split" in r}
        new = [r for r in group if "v1_split" not in r]
        if not new:
            continue
        if old_splits & {"val", "test"}:
            dropped_heldout += len(new)
            continue
        rng.shuffle(new)
        dropped_cap += max(0, len(new) - MAX_PER_CLUSTER)
        new = new[:MAX_PER_CLUSTER]
        (forced_train if old_splits else free).extend(new)
    logger.info(
        "dropped %d new rows near-duplicating v1 val/test, %d over the per-cluster cap; "
        "%d forced to train (near v1 train)",
        dropped_heldout,
        dropped_cap,
        len(forced_train),
    )

    new_train, new_val, new_test = grouped_stratified_split(
        free, rng, val_frac=VAL_FRAC, test_frac=TEST_FRAC
    )
    new_train += forced_train
    rng.shuffle(new_train)

    def strip(rows: list[dict]) -> list[dict]:
        return [{k: v for k, v in r.items() if k != "v1_split"} for r in rows]

    train = strip(v1["train"]) + new_train
    val = strip(v1["val"]) + new_val
    rng.shuffle(train)
    rng.shuffle(val)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT_DIR / "train.jsonl", train)
    write_jsonl(OUT_DIR / "val.jsonl", val)
    write_jsonl(OUT_DIR / "test.jsonl", new_test)

    def counts(rows: list[dict]) -> dict:
        labels = Counter(LABEL_NAMES[r["label"]] for r in rows)
        sources = Counter(f"{r.get('source', 'v1')}/{LABEL_NAMES[r['label']]}" for r in rows)
        return {
            "size": len(rows),
            "labels": dict(labels),
            "sources": dict(sorted(sources.items())),
        }

    stats = {
        "seed": SEED,
        "raw_file_sha256": digests,
        "dropped": {
            "near_v1_heldout": dropped_heldout,
            "over_cluster_cap": dropped_cap,
        },
        "train": counts(train),
        "val": counts(val),
        "test_new_locked": counts(new_test),
        "test_new_sha256": hashlib.sha256((OUT_DIR / "test.jsonl").read_bytes()).hexdigest(),
        "test_old": "training/data/test.jsonl (v1, unchanged)",
    }
    (OUT_DIR / "stats.json").write_text(json.dumps(stats, indent=2))
    logger.info("wrote %s", OUT_DIR)
    print(json.dumps({k: v for k, v in stats.items() if k != "raw_file_sha256"}, indent=2))


if __name__ == "__main__":
    main()
