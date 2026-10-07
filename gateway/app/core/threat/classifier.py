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

# Windowing for score_texts(). WINDOW_TOKENS + the 2 special tokens matches
# training/train_classifier.py's MAX_LENGTH of 160, so inference sees the
# same sequence length the model was trained on. The stride overlaps
# windows by 32 tokens so an injection split across a boundary still
# appears whole in one window.
WINDOW_TOKENS = 158
WINDOW_STRIDE = 126
INFERENCE_BATCH_SIZE = 8
# Bounds per-request cost (~4,000 tokens). Anything past this is not
# scanned; ScanResult.truncated reports it so the decision layer (module 6)
# can treat an oversized prompt as suspicious instead of silently trusting it.
MAX_WINDOWS = 32


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


@dataclass
class ScanResult:
    score: ThreatScore
    windows: int
    truncated: bool


class ThreatClassifier:
    """Loads a fine-tuned 3-class DeBERTa checkpoint and scores text.

    Runs on GPU if available, CPU otherwise. Measured cost (see
    training/README.md): ~20-60ms per short prompt on the RTX 3050 laptop
    GPU, ~160-230ms on CPU, growing linearly with prompt length (~1.5s on
    CPU for ~1,000 tokens) because every window is scored.
    """

    def __init__(self, checkpoint_dir: Path | str | None = None):
        # Imported lazily, not at module import time, so importing this
        # module (e.g. from a unit test that only wants ThreatScore or the
        # singleton helpers) never requires torch/transformers to be
        # installed unless an actual ThreatClassifier is instantiated.
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        resolved_dir = Path(checkpoint_dir or settings.THREAT_MODEL_DIR or DEFAULT_CHECKPOINT_DIR)
        # Checks for the config file, not just the directory: a Docker bind
        # mount of a missing host path creates an empty directory, which
        # would otherwise surface as an obscure transformers error.
        if not (resolved_dir / "config.json").exists():
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
        return self.score_texts([text]).score

    def score_texts(self, texts: list[str]) -> "ScanResult":
        """Score every window of every text and return the most suspicious one.

        Each text is split into overlapping windows of WINDOW_TOKENS (the
        training sequence length), so an injection can't hide past a
        truncation point behind padding. Texts are windowed separately, so a
        window never straddles two messages. The returned score is the
        full distribution of the window with the lowest `benign`
        probability - still a valid distribution, unlike a per-class max.
        """
        windows: list[list[int]] = []
        for text in texts:
            ids = self._tokenizer(text or "", add_special_tokens=False)["input_ids"]
            start = 0
            while True:
                windows.append(ids[start : start + WINDOW_TOKENS])
                if start + WINDOW_TOKENS >= len(ids):
                    break
                start += WINDOW_STRIDE
        if not windows:
            windows = [[]]

        truncated = len(windows) > MAX_WINDOWS
        windows = windows[:MAX_WINDOWS]

        tok = self._tokenizer
        best: list[float] | None = None
        with self._torch.inference_mode():
            for i in range(0, len(windows), INFERENCE_BATCH_SIZE):
                batch = [
                    [tok.cls_token_id, *w, tok.sep_token_id]
                    for w in windows[i : i + INFERENCE_BATCH_SIZE]
                ]
                width = max(len(ids) for ids in batch)
                input_ids = [ids + [tok.pad_token_id] * (width - len(ids)) for ids in batch]
                attention = [[1] * len(ids) + [0] * (width - len(ids)) for ids in batch]
                logits = self._model(
                    input_ids=self._torch.tensor(input_ids, device=self._device),
                    attention_mask=self._torch.tensor(attention, device=self._device),
                ).logits
                for probs in self._torch.softmax(logits, dim=-1).tolist():
                    if best is None or probs[0] < best[0]:
                        best = probs
        score = ThreatScore(**dict(zip(LABELS, best, strict=True)))
        return ScanResult(score=score, windows=len(windows), truncated=truncated)


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
