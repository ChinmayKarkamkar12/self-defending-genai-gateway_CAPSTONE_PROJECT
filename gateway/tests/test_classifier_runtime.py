"""Checks that torch + transformers actually work together on this host.

test_classifier.py needs the trained checkpoint, which isn't in git, so it
skips in CI - which once let a broken torch/transformers pairing through:
torch 2.6 with transformers 5.19 can't even import
AutoModelForSequenceClassification on a CPU-only machine. These tests need
no checkpoint and no download: they build a tiny randomly-initialised
DeBERTa-v2 (the checkpoint's architecture) and run it on CPU.
"""
import torch
from transformers import AutoModelForSequenceClassification, DebertaV2Config


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


def test_sequence_classifier_runs_on_cpu():
    model = tiny_deberta()
    input_ids = torch.tensor([[1, 5, 6, 7, 2, 0], [1, 8, 2, 0, 0, 0]])
    attention_mask = (input_ids != 0).long()

    with torch.inference_mode():
        logits = model(input_ids=input_ids, attention_mask=attention_mask).logits

    assert logits.shape == (2, 3)
    probs = torch.softmax(logits, dim=-1)
    assert torch.allclose(probs.sum(dim=-1), torch.ones(2))


def test_padding_does_not_change_prediction():
    # ThreatClassifier.score_texts pads windows into a batch by hand; padded
    # positions must be fully masked out.
    model = tiny_deberta()
    single = torch.tensor([[1, 5, 6, 7, 2]])
    padded = torch.tensor([[1, 5, 6, 7, 2, 0, 0, 0]])

    with torch.inference_mode():
        a = model(input_ids=single, attention_mask=torch.ones_like(single)).logits
        b = model(input_ids=padded, attention_mask=(padded != 0).long()).logits

    assert torch.allclose(a, b, atol=1e-5)
