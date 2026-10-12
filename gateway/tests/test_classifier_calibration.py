"""Temperature scaling of the threat classifier's scores (training/calibrate.py
writes calibration.json next to the checkpoint). Needs no checkpoint: the
scoring path is exercised with a tiny random DeBERTa, as in
test_classifier_runtime.py."""

import json
import math

import pytest
import torch
from transformers import AutoModelForSequenceClassification, DebertaV2Config

from app.core.threat.classifier import CALIBRATION_FILE, ThreatClassifier, load_temperature


def tiny_deberta() -> torch.nn.Module:
    config = DebertaV2Config(
        vocab_size=100,
        hidden_size=32,
        num_hidden_layers=1,
        num_attention_heads=2,
        intermediate_size=37,
        max_position_embeddings=64,
        num_labels=3,
    )
    return AutoModelForSequenceClassification.from_config(config).eval()


def test_no_calibration_file_means_raw_probabilities(tmp_path):
    assert load_temperature(tmp_path) == 1.0


def test_reads_fitted_temperature(tmp_path):
    (tmp_path / CALIBRATION_FILE).write_text(json.dumps({"temperature": 2.5, "val_size": 830}))
    assert load_temperature(tmp_path) == 2.5


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"val_size": 830}),
        json.dumps({"temperature": "warm"}),
        json.dumps({"temperature": None}),
        json.dumps({"temperature": 0}),
        json.dumps({"temperature": -1.0}),
        json.dumps({"temperature": 1e6}),
        '{"temperature": NaN}',
    ],
)
def test_unusable_calibration_file_fails_loudly(tmp_path, content):
    (tmp_path / CALIBRATION_FILE).write_text(content)
    with pytest.raises(ValueError):
        load_temperature(tmp_path)


class _Tok:
    cls_token_id, sep_token_id, pad_token_id = 1, 2, 0


def _classifier(temperature: float) -> ThreatClassifier:
    clf = object.__new__(ThreatClassifier)
    torch.manual_seed(0)
    clf._model = tiny_deberta()
    clf._tokenizer = _Tok()
    clf._device = torch.device("cpu")
    clf._torch = torch
    clf._temperature = temperature
    return clf


def test_scores_are_softmax_of_logits_over_temperature():
    windows = [[5, 6, 7], [8, 9], [10, 11, 12, 13]]
    clf = _classifier(3.0)
    probs = clf._window_probs(windows)

    with torch.inference_mode():
        for window, p in zip(windows, probs, strict=True):
            ids = torch.tensor([[1, *window, 2]])
            logits = clf._model(input_ids=ids, attention_mask=torch.ones_like(ids)).logits[0]
            expected = torch.softmax(logits / 3.0, dim=-1).tolist()
            assert p == pytest.approx(expected, abs=1e-5)


def test_temperature_softens_scores_without_changing_the_argmax():
    windows = [[5, 6, 7], [8, 9], [10, 11, 12, 13]]
    raw = _classifier(1.0)._window_probs(windows)
    soft = _classifier(3.0)._window_probs(windows)

    for r, s in zip(raw, soft, strict=True):
        assert math.isclose(sum(s), 1.0, rel_tol=1e-6)
        assert r.index(max(r)) == s.index(max(s))
        assert max(s) <= max(r) + 1e-9  # closer to uniform
