import tiktoken

from app.core.governance.token_counter import estimate_input_tokens, extract_usage


def test_tiktoken_count_matches_expected():
    text = "hello, world! this is a fixed test string."
    encoding = tiktoken.encoding_for_model("gpt-4o")
    expected = len(encoding.encode(text))

    actual = estimate_input_tokens("gpt-4o", [{"role": "user", "content": text}])

    assert actual == expected


def test_estimate_input_tokens_sums_multiple_messages():
    messages = [
        {"role": "system", "content": "be helpful"},
        {"role": "user", "content": "hi"},
    ]
    total = estimate_input_tokens("gpt-4o", messages)
    per_message = sum(estimate_input_tokens("gpt-4o", [m]) for m in messages)
    assert total == per_message


def test_extract_usage_reads_provider_response():
    response = {"usage": {"prompt_tokens": 12, "completion_tokens": 34}}
    tokens_in, tokens_out = extract_usage(response)
    assert (tokens_in, tokens_out) == (12, 34)


def test_extract_usage_defaults_to_zero_when_missing():
    assert extract_usage({}) == (0, 0)
