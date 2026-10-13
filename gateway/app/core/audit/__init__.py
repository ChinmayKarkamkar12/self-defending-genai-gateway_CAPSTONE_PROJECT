"""Tamper-evident audit logging (module 7). See project_plan/07-audit-logging.md."""
from app.core.audit import guard  # noqa: F401 - registers the append-only ORM guard
