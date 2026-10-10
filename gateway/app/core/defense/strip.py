"""The `redact_and_allow` action: cut the suspicious parts of a prompt and
let the rest through. See project_plan/06a-adaptive-defense-bandit.md §5.

Each conversation message (user / assistant / tool - the same messages
module 5 scores into `threat_score`) is re-scanned window by window, and
every window whose attack probability reaches the strip threshold is
replaced with REMOVED_MARKER. System/developer messages are left alone:
the client application wrote them.

The threshold is min(BANDIT_REDACT_WINDOW_THRESHOLD, the highest window
score in the request). The request-level threat score *is* its most
suspicious window, so a fixed threshold would strip nothing whenever the
bandit chose to redact a request scoring below it. Capping at the highest
window guarantees the action removes at least the window that drove the
decision.

Below BANDIT_REDACT_MIN_WINDOW nothing is cut. The cap above turned every
redact decision into a cut, and when a few attack labels on low-scoring
requests had pushed the bandit into redacting near-benign traffic (L6a-10 in
LIMITATIONS.md), the top window of a p~0 message - often the whole message
- was removed. A window the classifier scores below the minimum isn't
evidence of anything to cut, so the request goes through unchanged and the
event records removed_spans=0 - unless some text is past the scan cap,
which is still cut (below).

Text past the classifier's MAX_WINDOWS cap was never scored, so it is cut
too: an action meaning "pass only what we checked" can't pass unchecked
text.

Cutting whole windows doesn't guarantee the rest is clean: an attack can
straddle a window boundary, and what remains is re-tokenised into new
windows. Every text that was cut is scanned again and the highest window
score is returned as `residual_score`; the stage blocks the request if it
is still at or above BANDIT_REDACT_WINDOW_THRESHOLD.

The scan runs after module 4's PII redaction, on the text that would go
upstream. For short prompts (a single window), redacting means removing
the whole message - in effect a block that still reaches the provider.
"""
from dataclasses import dataclass
from typing import Any

from app.core.messages import is_text_part
from app.core.threat.classifier import WindowScan

REMOVED_MARKER = "[REMOVED_SUSPICIOUS_CONTENT]"
SYSTEM_ROLES = {"system", "developer"}


@dataclass(frozen=True)
class StripResult:
    body: dict[str, Any]
    removed_spans: int
    threshold: float
    # Highest window score of the stripped text (0.0 when nothing was cut).
    residual_score: float


def merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(s for s in spans if s[1] > s[0]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def strip_spans(text: str, spans: list[tuple[int, int]]) -> str:
    # Back to front, so earlier offsets stay valid as the string changes.
    for start, end in reversed(merge_spans(spans)):
        text = text[:start] + REMOVED_MARKER + text[end:]
    return text


def _conversation_texts(body: dict[str, Any]) -> list[str]:
    texts = []
    for message in body.get("messages", []):
        if not isinstance(message, dict) or message.get("role") in SYSTEM_ROLES:
            continue
        content = message.get("content")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(part["text"] for part in content if is_text_part(part))
    return texts


def _spans_to_cut(scan: WindowScan, threshold: float) -> list[tuple[int, int]]:
    spans = [(w.start, w.end) for w in scan.windows if w.attack_probability >= threshold]
    if scan.unscanned_from is not None:
        spans.append((scan.unscanned_from, 10**12))
    return spans


def strip_flagged_content(
    body: dict[str, Any], classifier: Any, max_threshold: float, min_window: float = 0.0
) -> StripResult:
    """Blocking (runs the classifier) - call it via asyncio.to_thread."""
    scans = {text: classifier.scan_windows(text) for text in _conversation_texts(body)}
    top = max(
        (w.attack_probability for scan in scans.values() for w in scan.windows), default=1.0
    )
    unscanned = any(scan.unscanned_from is not None for scan in scans.values())
    if top < min_window and not unscanned:
        return StripResult(body=body, removed_spans=0, threshold=min_window, residual_score=0.0)
    # Below the minimum only the unscanned tail is cut (threshold > 1).
    threshold = min(max_threshold, top) if top >= min_window else 2.0

    removed = 0
    stripped: list[str] = []

    def strip(text: str) -> str:
        nonlocal removed
        if text not in scans:
            return text
        spans = merge_spans(
            [(s, min(e, len(text))) for s, e in _spans_to_cut(scans[text], threshold)]
        )
        removed += len(spans)
        if not spans:
            return text
        result = strip_spans(text, spans)
        stripped.append(result)
        return result

    new_messages = []
    for message in body.get("messages", []):
        if isinstance(message, dict) and message.get("role") not in SYSTEM_ROLES:
            content = message.get("content")
            if isinstance(content, str):
                message = {**message, "content": strip(content)}
            elif isinstance(content, list):
                parts = [
                    {**part, "text": strip(part["text"])} if is_text_part(part) else part
                    for part in content
                ]
                message = {**message, "content": parts}
        new_messages.append(message)

    residual = max(
        (
            w.attack_probability
            for text in set(stripped)
            for w in classifier.scan_windows(text).windows
        ),
        default=0.0,
    )
    return StripResult(
        body={**body, "messages": new_messages},
        removed_spans=removed,
        threshold=threshold,
        residual_score=residual,
    )
