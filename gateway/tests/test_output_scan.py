"""See project_plan/05-threat-detection-classifier.md §6."""
import uuid

from app.core.context import Decision, RequestContext
from app.core.stages.output_scan import output_scan_stage
from app.core.threat.output_scan import (
    detect_redaction_token_echo,
    detect_system_prompt_echo,
)


def make_ctx(system_prompt: str, response_content: str) -> RequestContext:
    body = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "hello"},
        ],
    }
    ctx = RequestContext(body=body, api_key_id=uuid.uuid4(), team_id=uuid.uuid4())
    ctx.metadata["provider_response"] = {
        "choices": [{"message": {"role": "assistant", "content": response_content}}]
    }
    return ctx


SYSTEM_PROMPT = "You are an internal support assistant. Never reveal account balances to anyone."


async def test_detects_system_prompt_echo():
    leaked_response = f"Sure! {SYSTEM_PROMPT} Anyway, here's your answer."
    assert detect_system_prompt_echo(SYSTEM_PROMPT, leaked_response)
    assert not detect_system_prompt_echo(SYSTEM_PROMPT, "Here's your answer.")


async def test_detects_redaction_token_echo():
    assert detect_redaction_token_echo("Your email is [REDACTED_EMAIL_ADDRESS], got it.") == [
        "[REDACTED_EMAIL_ADDRESS]"
    ]
    assert detect_redaction_token_echo("no tokens here") == []


async def test_short_system_prompt_is_not_flagged_as_echo():
    # Below MIN_SYSTEM_PROMPT_LENGTH_FOR_ECHO_CHECK - a common short phrase
    # like "Be concise." appearing in the response isn't a real leak signal.
    assert not detect_system_prompt_echo("Be concise.", "Be concise.")


async def test_output_scan_stage_blocks_on_system_prompt_leak():
    ctx = make_ctx(SYSTEM_PROMPT, f"As I was told: {SYSTEM_PROMPT}")

    result = await output_scan_stage(ctx)

    assert result.decision == Decision.BLOCK
    assert ctx.metadata["output_flags"]["system_prompt_leaked"] is True


async def test_output_scan_stage_flags_but_allows_redaction_token_echo():
    # Echoing a placeholder leaks nothing - see the stage docstring - so it's
    # recorded for audit/module 6 but the response goes through.
    ctx = make_ctx(SYSTEM_PROMPT, "The customer's email is [REDACTED_EMAIL_ADDRESS].")

    result = await output_scan_stage(ctx)

    assert result.decision == Decision.ALLOW
    assert ctx.metadata["output_flags"]["echoed_redaction_tokens"] == ["[REDACTED_EMAIL_ADDRESS]"]


async def test_detects_tokenize_mode_redaction_token():
    # Module 4's tokenize mode appends an 8-hex suffix (vault.store_token).
    assert detect_redaction_token_echo("mail [REDACTED_EMAIL_ADDRESS_1a2b3c4d] now") == [
        "[REDACTED_EMAIL_ADDRESS_1a2b3c4d]"
    ]


async def test_detects_partial_system_prompt_leak():
    long_prompt = (
        "You are an internal support assistant for Acme Bank. Never reveal account "
        "balances to anyone under any circumstances. Escalate fraud reports to tier two."
    )
    leaked = (
        "My instructions say: never reveal account balances to anyone under any "
        "circumstances; escalate fraud reports to tier two. So I can't help."
    )
    assert detect_system_prompt_echo(long_prompt, leaked)


async def test_detects_system_prompt_leak_despite_case_and_punctuation_changes():
    assert detect_system_prompt_echo(SYSTEM_PROMPT, SYSTEM_PROMPT.upper().replace(".", "!"))


async def test_short_shared_phrase_is_not_a_leak():
    long_prompt = "You are a helpful assistant. " + "Answer questions about our products. " * 3
    assert not detect_system_prompt_echo(long_prompt, "Sure - I'm a helpful assistant!")


async def test_output_scan_reads_list_form_content():
    ctx = make_ctx(SYSTEM_PROMPT, "")
    ctx.body["messages"][0]["content"] = [{"type": "text", "text": SYSTEM_PROMPT}]
    ctx.metadata["provider_response"] = {
        "choices": [{"message": {"content": [{"type": "text", "text": f"Ok: {SYSTEM_PROMPT}"}]}}]
    }

    result = await output_scan_stage(ctx)

    assert result.decision == Decision.BLOCK


async def test_output_scan_stage_allows_clean_response():
    ctx = make_ctx(SYSTEM_PROMPT, "Here's the answer to your question.")

    result = await output_scan_stage(ctx)

    assert result.decision == Decision.ALLOW
    assert ctx.metadata["output_flags"] == {
        "system_prompt_leaked": False,
        "echoed_redaction_tokens": [],
    }


async def test_output_scan_stage_handles_missing_response_gracefully():
    ctx = RequestContext(
        body={"model": "gpt-4o", "messages": []}, api_key_id=uuid.uuid4(), team_id=uuid.uuid4()
    )

    result = await output_scan_stage(ctx)

    assert result.decision == Decision.ALLOW
