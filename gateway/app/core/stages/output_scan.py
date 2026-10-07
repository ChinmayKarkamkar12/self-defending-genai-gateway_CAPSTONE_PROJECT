"""Provider-response scanning stage (post-call). See
project_plan/05-threat-detection-classifier.md §4.

Unlike `threat_detection_stage`, this one *can* block directly: a system
prompt either reappears in the response as a long verbatim word run or it
doesn't, which is binary enough not to need module 6's bandit judgment
call the way a threat *score* does.

Redaction-token echoes are flagged, not blocked. A response that reuses a
`[REDACTED_...]` placeholder leaks nothing - the placeholder is what module
4 already sent upstream in place of the real value - and it's the normal
result of an ordinary request like "draft an email to <redacted address>".
Blocking it would break legitimate traffic for no security gain. The flag
stays in `output_flags` so audit logging (module 7) and the defense layer
(module 6) can still see it.

A BLOCK here becomes a 422 from app/api/chat.py, consistent with every
other pipeline block, rather than a 200 carrying a synthetic refusal.
"""
from app.core.context import RequestContext, StageResult
from app.core.threat.output_scan import (
    detect_redaction_token_echo,
    detect_system_prompt_echo,
    extract_response_text,
    extract_system_prompt,
)


async def output_scan_stage(ctx: RequestContext) -> StageResult:
    response = ctx.metadata.get("provider_response", {})
    response_text = extract_response_text(response)
    system_prompt = extract_system_prompt(ctx.body)

    system_prompt_leaked = detect_system_prompt_echo(system_prompt, response_text)
    echoed_tokens = detect_redaction_token_echo(response_text)

    ctx.metadata["output_flags"] = {
        "system_prompt_leaked": system_prompt_leaked,
        "echoed_redaction_tokens": echoed_tokens,
    }

    if system_prompt_leaked:
        return StageResult.block("response leaked the system prompt")
    return StageResult.allow()
