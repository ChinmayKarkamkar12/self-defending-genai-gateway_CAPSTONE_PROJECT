"""Helpers for reading text out of OpenAI-shaped chat messages.

A message's `content` is either a plain string or a list of typed parts
(`[{"type": "text", "text": "..."}, {"type": "image_url", ...}]`). Every
stage that inspects prompt or response text must handle both forms - a
stage that only reads string content can be bypassed entirely by sending
the same text as a one-element parts list.
"""
from typing import Any

TEXT_PART_TYPES = {"text", "input_text", "output_text"}


def is_text_part(part: Any) -> bool:
    return (
        isinstance(part, dict)
        and part.get("type") in TEXT_PART_TYPES
        and isinstance(part.get("text"), str)
    )


def content_text_parts(content: Any) -> list[str]:
    """Every text segment in a message's `content`, in order."""
    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        return [part["text"] for part in content if is_text_part(part)]
    return []


def message_text(message: dict[str, Any]) -> str:
    return "\n".join(content_text_parts(message.get("content")))
