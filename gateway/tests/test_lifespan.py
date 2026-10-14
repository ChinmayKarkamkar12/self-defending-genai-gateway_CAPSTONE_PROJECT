"""The app's startup and shutdown (app/main.py's lifespan).

ASGITransport never runs the lifespan, so the rest of the suite sets up
what it would by hand. This runs the real one - with conftest's fake
classifier standing in for the checkpoint load - to check it wires up and
tears down what production depends on (module 9: it had no test).
"""
from app.core.audit.writer import AuditWriter, reset_audit_writer, set_audit_writer
from app.core.providers import registry
from app.core.threat.classifier import get_threat_classifier
from app.main import app
from tests.conftest import FakeThreatClassifier


async def test_lifespan_starts_and_stops_what_requests_depend_on(session_maker):
    writer = AuditWriter(session_maker)
    set_audit_writer(writer)
    providers = (registry._OPENAI, registry._ANTHROPIC)
    try:
        async with app.router.lifespan_context(app):
            # The classifier is loaded before the first request...
            assert isinstance(get_threat_classifier(), FakeThreatClassifier)
            # ...the audit writer is running...
            assert writer.running
            # ...and each provider has its one pooled client (L2-2).
            assert all(p.http.is_open for p in providers)

        # Shutdown drains the writer and closes the pooled clients.
        assert not writer.running
        assert not any(p.http.is_open for p in providers)
    finally:
        reset_audit_writer()
