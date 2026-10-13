"""Tamper-evident audit logging stage (module 7). See project_plan/07-audit-logging.md §4.

Assembles the request's audit entry from `ctx.metadata` and hands it to the
background writer's queue. Enqueueing never waits on the database, so this
adds no meaningful latency; the writer chains and stores the entry after
the response has gone. If the entry can't be queued (queue full, writer not
running), this raises, and FAIL_MODE decides: closed (default) turns the
request into a 503 rather than an unaudited success.

Called by the chat endpoint on every exit path for an authenticated
request - allowed, blocked by any stage, or failed - not only on success.
"""
from app.core.audit.entry import build_audit_record
from app.core.audit.writer import get_audit_writer
from app.core.context import RequestContext, StageResult


async def audit_log_stage(ctx: RequestContext) -> StageResult:
    get_audit_writer().enqueue(build_audit_record(ctx))
    return StageResult.allow()
