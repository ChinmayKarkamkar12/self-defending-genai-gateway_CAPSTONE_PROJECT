from app.core.defense.strip import (
    REMOVED_MARKER,
    merge_spans,
    strip_flagged_content,
    strip_spans,
)
from app.core.threat.classifier import WindowScan, WindowSpan


class WindowedFake:
    """Scores fixed-size character windows: a window is an attack if it
    contains the word EVIL."""

    def __init__(self, size: int = 10, unscanned_after: int | None = None, hit: float = 0.97):
        self.size = size
        self.unscanned_after = unscanned_after
        self.hit = hit

    def scan_windows(self, text: str) -> WindowScan:
        limit = len(text) if self.unscanned_after is None else min(len(text), self.unscanned_after)
        windows = [
            WindowSpan(
                start=i,
                end=min(i + self.size, limit),
                attack_probability=self.hit if "EVIL" in text[i : i + self.size] else 0.01,
            )
            for i in range(0, limit, self.size)
        ]
        return WindowScan(windows=windows, unscanned_from=self.unscanned_after)


def test_merge_spans():
    assert merge_spans([(5, 8), (0, 3), (2, 4), (8, 9), (12, 12)]) == [(0, 4), (5, 9)]


def test_strip_spans():
    assert strip_spans("abcdefghij", [(2, 4), (3, 6)]) == f"ab{REMOVED_MARKER}ghij"


def test_strips_flagged_window_and_leaves_rest():
    body = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "EVIL-looking but app-authored"},
            {"role": "user", "content": "aaaaaaaaaaEVILbbbbbbcccccccccc"},
        ],
    }
    result = strip_flagged_content(body, WindowedFake(), max_threshold=0.5)
    assert result.body["messages"][1]["content"] == f"aaaaaaaaaa{REMOVED_MARKER}cccccccccc"
    assert result.body["messages"][0] == body["messages"][0]
    assert result.removed_spans == 1
    assert body["messages"][1]["content"] == "aaaaaaaaaaEVILbbbbbbcccccccccc"  # not mutated


def test_threshold_capped_at_top_window_so_something_is_always_cut():
    # No window reaches 0.5, but the bandit still chose to redact: the
    # most suspicious window goes.
    body = {"messages": [{"role": "user", "content": "aaaaaaaaaaEVILbbbbbb"}]}
    result = strip_flagged_content(body, WindowedFake(hit=0.3), max_threshold=0.5)
    assert result.threshold == 0.3
    assert result.body["messages"][0]["content"] == f"aaaaaaaaaa{REMOVED_MARKER}"


def test_list_content_text_parts_stripped():
    image = {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
    body = {
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": "EVILxxxxxxyyyyyyyyyy"}, image],
            }
        ]
    }
    result = strip_flagged_content(body, WindowedFake(), max_threshold=0.5)
    parts = result.body["messages"][0]["content"]
    assert parts[0]["text"] == f"{REMOVED_MARKER}yyyyyyyyyy"
    assert parts[1] == image


def test_unscanned_tail_is_cut():
    body = {"messages": [{"role": "user", "content": "EVILxxxxxx" + "z" * 50}]}
    result = strip_flagged_content(body, WindowedFake(unscanned_after=20), max_threshold=0.5)
    assert result.body["messages"][0]["content"] == f"{REMOVED_MARKER}zzzzzzzzzz{REMOVED_MARKER}"
