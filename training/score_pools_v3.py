"""Score the session agent's v3 prompt pools with the production classifier
(data expansion, see training/README.md "Data expansion (v2)").

  rl3_train = training/data/v2/val.jsonl  (v1 val + new val)
  rl3_test  = training/data/test.jsonl + training/data/v2/test.jsonl
              (old test + the new locked test)

Neither was used to fit the classifier's weights. The scores are cached as
training/data/bandit_scores_rl3_{train,test}.jsonl in the same format as
evaluate_bandit.py's cache (scores and labels only, no text), which
generate_sessions.load_pools reads.

Run from the repo root after choosing the classifier (THREAT_MODEL_DIR
selects the checkpoint; its calibration.json temperature is applied, as in
the gateway):
    gateway/.venv/Scripts/python.exe training/score_pools_v3.py --checkpoint <dir>
"""

import argparse
import json
from pathlib import Path

import generate_sessions as gs

from app.core.threat.classifier import ThreatClassifier

SOURCES = {
    "rl3_train": [gs.DATA_DIR / "v2" / "val.jsonl"],
    "rl3_test": [gs.DATA_DIR / "test.jsonl", gs.DATA_DIR / "v2" / "test.jsonl"],
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args()
    classifier = ThreatClassifier(args.checkpoint)

    for pool, files in SOURCES.items():
        lines = []
        for path in files:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                result = classifier.score_texts([row["text"]])
                lines.append(
                    json.dumps(
                        {
                            "threat_score": result.score.as_dict(),
                            "windows": result.windows,
                            "truncated": result.truncated,
                            "is_attack": row["label"] != 0,
                        }
                    )
                )
        out = gs.DATA_DIR / f"bandit_scores_{pool}.jsonl"
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        attacks = sum('"is_attack": true' in line for line in lines)
        print(f"{pool}: {len(lines)} prompts ({attacks} attacks) -> {out.name}")


if __name__ == "__main__":
    main()
