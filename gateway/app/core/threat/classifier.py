"""Threat classifier inference wrapper. See
project_plan/05-threat-detection-classifier.md §3.

The model is loaded once (see `app/main.py`'s startup hook) and reused for
every request via the module-level singleton below - never re-loaded
per-request. `set_threat_classifier`/`reset_threat_classifier` exist purely
so tests can inject a cheap fake instead of loading the real checkpoint
(torch + a ~500MB DeBERTa checkpoint has no business running inside unit
tests - see gateway/tests/test_threat_stage.py).
"""
import logging
from dataclasses import dataclass
from pathlib import Path

from app.config import settings

logger = logging.getLogger("gateway.threat")

LABELS = ["benign", "prompt_injection", "jailbreak"]

# training/checkpoints/final/ lives at the repo root, two levels above
# gateway/ - this file is gateway/app/core/threat/classifier.py, so
# parents[4] is the repo root. Overridable via THREAT_MODEL_DIR for
# deployments that keep the checkpoint somewhere else (e.g. a mounted
# volume in the Docker image - see project_plan/10-deployment-docker-compose.md).
_REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CHECKPOINT_DIR = _REPO_ROOT / "training" / "checkpoints" / "final"


@dataclass
class ThreatScore:
    benign: float
    prompt_injection: float
    jailbreak: float

    def as_dict(self) -> dict[str, float]:
        return {
            "benign": self.benign,
            "prompt_injection": self.prompt_injection,
            "jailbreak": self.jailbreak,
        }


class ThreatClassifier:
    """Loads a fine-tuned 3-class DeBERTa checkpoint and scores text.

    Runs on GPU if available, CPU otherwise - CPU inference on a
    base-sized DeBERTa adds roughly 50-150ms per request on a typical
    laptop/server CPU, which is acceptable for a low-QPS demo deployment
    but worth knowing about before assuming GPU-like latency in production.
    """

    def __init__(self, checkpoint_dir: Path | str | None = None):
        # Imported lazily, not at module import time, so importing this
        # module (e.g. from a unit test that only wants ThreatScore or the
        # singleton helpers) never requires torch/transformers to be
        # installed unless an actual ThreatClassifier is instantiated.
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        resolved_dir = Path(checkpoint_dir or settings.THREAT_MODEL_DIR or DEFAULT_CHECKPOINT_DIR)
        if not resolved_dir.exists():
            raise FileNotFoundError(
                f"threat classifier checkpoint not found at {resolved_dir} - run "
                "training/prepare_dataset.py and training/train_classifier.py first, "
                "or set THREAT_MODEL_DIR to an existing checkpoint directory"
            )

        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._tokenizer = AutoTokenizer.from_pretrained(resolved_dir)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            resolved_dir, dtype=torch.float32
        )
        self._model.to(self._device)
        self._model.eval()
        self._torch = torch
        logger.info("ThreatClassifier loaded from %s onto %s", resolved_dir, self._device)

    def score(self, text: str) -> ThreatScore:
        with self._torch.inference_mode():
            inputs = self._tokenizer(
                text or "",
                return_tensors="pt",
                truncation=True,
                max_length=256,
                padding=True,
            ).to(self._device)
            logits = self._model(**inputs).logits
            probs = self._torch.softmax(logits, dim=-1).squeeze(0).tolist()
        return ThreatScore(**dict(zip(LABELS, probs, strict=True)))


_classifier: ThreatClassifier | None = None


def get_threat_classifier() -> ThreatClassifier:
    """Returns the process-wide singleton, loading it on first call if
    `app/main.py`'s startup hook hasn't already done so."""
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
    return _classifier


def set_threat_classifier(classifier: ThreatClassifier) -> None:
    """Test-only hook to inject a fake classifier (or the real one, with a
    custom checkpoint dir) without going through the lazy singleton path."""
    global _classifier
    _classifier = classifier


def reset_threat_classifier() -> None:
    """Test-only hook to clear the singleton so the next `get_threat_classifier()`
    call re-loads from disk. Mirrors `set_threat_classifier(None)` but reads
    clearer at call sites that just want a clean slate between tests."""
    global _classifier
    _classifier = None
