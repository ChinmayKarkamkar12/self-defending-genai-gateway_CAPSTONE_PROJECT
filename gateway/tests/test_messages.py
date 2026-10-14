"""app/core/messages.py: the text every stage reads out of a message."""
import json

from app.core.messages import argument_text, message_text


def test_argument_text_keeps_string_values_and_drops_the_json():
    arguments = json.dumps(
        {
            "query": "onboarding guide",
            "filters": {"team": "IT", "tags": ["laptop", "", "vpn"]},
            "limit": 5,
            "exact": True,
        }
    )

    assert argument_text(arguments) == "onboarding guide\nIT\nlaptop\nvpn"


def test_argument_text_returns_invalid_json_unchanged():
    assert argument_text("not json {") == "not json {"
    assert argument_text('"just a string"') == "just a string"


def test_argument_text_survives_very_deep_nesting():
    deep = "[" * 5000 + '"x"' + "]" * 5000
    # json.loads gives up on this; either way the stage must not crash.
    assert argument_text(deep) in ("x", deep)


def test_message_text_includes_tool_call_and_legacy_function_call_values():
    message = {
        "role": "assistant",
        "content": "Searching.",
        "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "f", "arguments": '{"q": "one"}'}},
            {"id": "b", "type": "function", "function": {"name": "g", "arguments": "{}"}},
            "not a call",
        ],
        "function_call": {"name": "h", "arguments": '{"q": "two"}'},
    }

    assert message_text(message) == "Searching.\none\ntwo"
