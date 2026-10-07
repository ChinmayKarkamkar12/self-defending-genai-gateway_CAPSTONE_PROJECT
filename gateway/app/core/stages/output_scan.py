"""Provider-response scanning stage (post-call). See
project_plan/05-threat-detection-classifier.md §4.

Unlike `threat_detection_stage`, this one *can* block directly: leakage
detection here is binary enough (the system prompt either appears
verbatim in the response or it doesn't; a `[REDACTED_...]` token either
got echoed back or it didn't) that it doesn't need module 6's bandit
judgment call the way a threat *score* does.
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
        return StageResult.block("response leaked the system prompt verbatim")
    if echoed_tokens:
        return StageResult.block("response echoed a redaction token from a previous stage")
    return StageResult.allow()
