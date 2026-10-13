"""Application-level append-only guard for AuditLogEntry.

The database-level guard is the trigger in migration 0008, which refuses
UPDATE/DELETE/TRUNCATE on Postgres. This is the second layer: it stops the
gateway's own code from ever issuing one through the ORM, on any database
(including the SQLite test suite, which has no trigger). Raw SQL through
`text()` is not ORM-level and is not caught here - that is what the trigger
and, past it, the hash chain are for. See docs/adr/0002-audit-log-immutability.md.

Registered on import of app.core.audit (see __init__.py).
"""
from sqlalchemy import event
from sqlalchemy.orm import ORMExecuteState, Session

from app.db.models import AuditLogEntry


class AuditLogImmutableError(Exception):
    """An attempt to update or delete an audit log entry."""


@event.listens_for(Session, "before_flush")
def _refuse_audit_entry_changes(session: Session, _flush_context, _instances) -> None:
    for obj in session.deleted:
        if isinstance(obj, AuditLogEntry):
            raise AuditLogImmutableError("audit log entries cannot be deleted")
    for obj in session.dirty:
        if isinstance(obj, AuditLogEntry) and session.is_modified(obj):
            raise AuditLogImmutableError("audit log entries cannot be modified")


@event.listens_for(Session, "do_orm_execute")
def _refuse_bulk_audit_changes(state: ORMExecuteState) -> None:
    # Bulk `update(AuditLogEntry)` / `delete(AuditLogEntry)` statements
    # bypass the flush, so before_flush never sees them.
    if not (state.is_update or state.is_delete):
        return
    if any(mapper.class_ is AuditLogEntry for mapper in state.all_mappers):
        raise AuditLogImmutableError("audit log entries cannot be modified or deleted")
