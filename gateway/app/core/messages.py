"""Helpers for reading text out of OpenAI-shaped chat messages.

A message's `content` is either a plain string or a list of typed parts
(`[{"type": "text", "text": "..."}, {"type": "image_url", ...}]`). Every
stage that inspects prompt or response text must handle both forms - a
stage that only reads string content can be bypassed entirely by sending
the same text as a one-element parts list.

An assistant message can also carry text outside `content`: the arguments
of the tool calls it makes (`tool_calls[].function.arguments`, or the
legacy `function_call.arguments`), a JSON string written by the model or
replayed by the client - an email address to send to, a document to
summarise. Module 9 found those reaching the provider unredacted and
unscored, so `message_text` includes them (their values, see
`argument_text`), and module 4 redacts them.
"""
import json
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


def tool_call_functions(message: dict[str, Any]) -> list[dict[str, Any]]:
    """The `function` object of every call `message` makes, legacy form included."""
    calls = message.get("tool_calls")
    functions = []
    if isinstance(calls, list):
        functions = [call.get("function") for call in calls if isinstance(call, dict)]
    functions.append(message.get("function_call"))
    return [
        function
        for function in functions
        if isinstance(function, dict) and isinstance(function.get("arguments"), str)
    ]


def argument_text(arguments: str) -> str:
    """The text a tool call's arguments carry: the string values inside the
    JSON, one per line, without the JSON around them.

    For the classifier, which was trained on natural-language prompts: raw
    JSON syntax itself scores as an attack (measured in module 9:
    `{"query": "onboarding guide for new employees"}` 0.979, the bare
    value 0.031). Keys are left out - the application's schema chose them,
    not the conversation. Arguments that aren't valid JSON are returned as
    they are.
    """
    try:
        parsed = json.loads(arguments)
    except (ValueError, RecursionError):
        return arguments
    values: list[str] = []
    pending = [parsed]
    while pending:  # iterative: a deeply nested payload can't exhaust the stack
        node = pending.pop()
        if isinstance(node, str):
            if node.strip():
                values.append(node)
        elif isinstance(node, dict):
            pending.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            pending.extend(reversed(node))
    return "\n".join(values)


def tool_call_texts(message: dict[str, Any]) -> list[str]:
    """`argument_text` of every call `message` makes, skipping empty ones."""
    texts = [argument_text(function["arguments"]) for function in tool_call_functions(message)]
    return [text for text in texts if text]


def message_text(message: dict[str, Any]) -> str:
    """All the text in a message: its content, then its tool call arguments."""
    return "\n".join(content_text_parts(message.get("content")) + tool_call_texts(message))
