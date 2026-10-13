"""Apply the pre-registered classifier replacement criteria (training/README.md,
"Pre-registered criteria") to evaluate.py outputs, so the decision is mechanical.

A candidate replaces v1 only if all hold:
  1. new test: candidate prompt_injection F1 > v1's;
  2. new test: candidate benign false-positive rate <= v1's;
  3. old test: candidate macro-F1 >= 0.913 and benign false-positive rate <= 0.02.

Run from the repo root:
    python training/apply_classifier_criteria.py --candidate v3
"""

import argparse
import json
from pathlib import Path

RESULTS_DIR = Path("training/checkpoints/v1_vs_v2")
OLD_MACRO_FLOOR = 0.913
OLD_FP_CEILING = 0.02


def load(name: str) -> dict:
    data = json.loads((RESULTS_DIR / f"{name}.json").read_text())
    report = data["report"]
    if isinstance(report, str):  # older outputs stored the dict's repr
        import ast

        report = ast.literal_eval(report)
    return {
        "injection_f1": report["prompt_injection"]["f1-score"],
        "jailbreak_f1": report["jailbreak"]["f1-score"],
        "macro_f1": report["macro avg"]["f1-score"],
        "benign_fp": data["benign_false_positive_rate"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True, help="e.g. v2 or v3")
    cand = parser.parse_args().candidate

    v1_new, v1_old = load("v1_new_test"), load("v1_old_test")
    c_new, c_old = load(f"{cand}_new_test"), load(f"{cand}_old_test")

    checks = [
        ("1. new-test injection F1 > v1", c_new["injection_f1"] > v1_new["injection_f1"],
         f"{c_new['injection_f1']:.3f} vs {v1_new['injection_f1']:.3f}"),
        ("2. new-test benign FP rate <= v1", c_new["benign_fp"] <= v1_new["benign_fp"],
         f"{c_new['benign_fp']:.3f} vs {v1_new['benign_fp']:.3f}"),
        ("3a. old-test macro-F1 >= 0.913", c_old["macro_f1"] >= OLD_MACRO_FLOOR,
         f"{c_old['macro_f1']:.3f}"),
        ("3b. old-test benign FP rate <= 0.02", c_old["benign_fp"] <= OLD_FP_CEILING,
         f"{c_old['benign_fp']:.3f}"),
    ]
    print(f"{'':28}{'v1':>8}{cand:>8}")
    for split, a, b in (("new", v1_new, c_new), ("old", v1_old, c_old)):
        for key in ("macro_f1", "injection_f1", "jailbreak_f1", "benign_fp"):
            print(f"{split} {key:23}{a[key]:8.3f}{b[key]:8.3f}")
    print()
    for label, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {label}  ({detail})")
    passed = all(ok for _, ok, _ in checks)
    print(f"\nRESULT: {cand} {'REPLACES v1' if passed else 'does NOT replace v1'}")


if __name__ == "__main__":
    main()
