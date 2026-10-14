"""Database setup, run once per start by the compose `migrate` service
(module 10) before the gateway starts. Connects as the database owner.

    python -m scripts.db_setup

1. `alembic upgrade head`.
2. Makes sure the gateway's own login role exists with only the rights it
   needs (LIMITATIONS.md L7-6): read and write the application tables, never
   own them. The gateway process then can't do what only an owner or a
   superuser can - disable the audit log's append-only trigger, TRUNCATE
   it, or switch triggers off with `session_replication_role` - and on
   `audit_log_entries` it can't UPDATE or DELETE at all, trigger or not.
   Re-run on every start, so tables added by later migrations get their
   grants too.
3. If DEMO_SEED is set, loads the demo teams, keys, policies and admin
   (scripts/seed_demo.py). Idempotent.

Environment:
    POSTGRES_DSN            the owner's DSN (superuser in the compose setup)
    POSTGRES_APP_USER       the gateway's role name (default gateway_app)
    POSTGRES_APP_PASSWORD   its password (required)
"""

import os
import sys
from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

from alembic import command

GATEWAY_DIR = Path(__file__).resolve().parents[1]
DEFAULT_APP_USER = "gateway_app"
# Read-only for the gateway: the audit log is append-only, migrations are the owner's.
INSERT_ONLY_TABLES = ("audit_log_entries",)
OWNER_ONLY_TABLES = ("alembic_version",)


def migrate() -> None:
    config = Config(str(GATEWAY_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(GATEWAY_DIR / "alembic"))
    command.upgrade(config, "head")


def _quoted(conn: Connection, template: str, *values: str) -> str:
    """Build a statement with Postgres's own quoting (%I identifier, %L
    literal): role names and passwords can't be bind parameters in DDL."""
    params = {f"v{i}": value for i, value in enumerate(values)}
    placeholders = ", ".join(f":{name}" for name in params)
    statement = text(f"SELECT format(:template, {placeholders})")
    return conn.execute(statement, {"template": template, **params}).scalar_one()


def ensure_app_role(conn: Connection, role: str, password: str) -> None:
    """Create or update `role` and grant it exactly what the gateway uses."""
    exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first()
    verb = "ALTER" if exists else "CREATE"
    conn.execute(
        text(
            _quoted(
                conn,
                verb + " ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
                "NOBYPASSRLS PASSWORD %L",
                role,
                password,
            )
        )
    )
    database = conn.execute(text("SELECT current_database()")).scalar_one()
    for template, *names in (
        ("GRANT CONNECT ON DATABASE %I TO %I", database, role),
        ("GRANT USAGE ON SCHEMA public TO %I", role),
        ("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I", role),
        ("GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %I", role),
    ):
        conn.execute(text(_quoted(conn, template, *names)))
    for table in INSERT_ONLY_TABLES:
        conn.execute(
            text(_quoted(conn, "REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM %I", table, role))
        )
    for table in OWNER_ONLY_TABLES:
        conn.execute(text(_quoted(conn, "REVOKE ALL ON %I FROM %I", table, role)))


def main() -> None:
    from app.config import settings

    password = os.environ.get("POSTGRES_APP_PASSWORD", "")
    if not password:
        sys.exit("POSTGRES_APP_PASSWORD is not set (see .env.example)")
    role = os.environ.get("POSTGRES_APP_USER", DEFAULT_APP_USER)

    print("db_setup: applying migrations", flush=True)
    migrate()
    engine = create_engine(settings.POSTGRES_DSN)
    try:
        with engine.begin() as conn:
            ensure_app_role(conn, role, password)
    finally:
        engine.dispose()
    print(f"db_setup: role '{role}' ready (no ownership, audit log insert-only)", flush=True)

    if os.environ.get("DEMO_SEED", "").lower() in ("1", "true", "yes"):
        import asyncio

        from scripts.seed_demo import seed_records

        asyncio.run(seed_records())


if __name__ == "__main__":
    main()
