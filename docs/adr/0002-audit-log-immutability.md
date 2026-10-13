# ADR-0002: How the audit log is kept append-only and tamper-evident

## Context

Module 7 records one audit entry per authenticated request: what each module
decided about it (cost, PII redaction counts, threat score, the bandit's
action, the session agent's action, the final outcome). The plan
(`project_plan/07-audit-logging.md` §7 task 1) asks for "a Postgres-level
trigger or application-level guard preventing UPDATE/DELETE on this table",
with the choice and the reasoning documented.

Two kinds of people could change the log:

1. **The application itself**, through a bug or a future feature that
   "cleans up" or "corrects" old entries.
2. **Someone with direct database access** - a DBA, or an attacker who has
   the database credentials - who wants to hide what happened, e.g. rewrite
   a blocked attack as allowed.

No guard inside the database can stop the second kind completely: a
superuser can disable triggers, drop them, or edit the table files. The
best we can do against them is to make a change *detectable*.

## Decision

Three layers, each covering what the one before it can't:

| Layer | Where | Stops / detects |
|---|---|---|
| ORM guard | `app/core/audit/guard.py` | The gateway's own code updating or deleting an entry through SQLAlchemy (per-object and bulk `update()`/`delete()`). Works on every database, including the SQLite test suite. |
| Postgres trigger | migration `0008` | Any `UPDATE`, `DELETE` or `TRUNCATE` on `audit_log_entries` from any client, unless a privileged user explicitly disables triggers. |
| Hash chain | `app/core/audit/hashing.py`, `verify.py` | Everything that gets past the first two layers: any edited field, any edited hash, any deleted or inserted row in the middle (sequence gap) is reported by `verify`, with the first broken entry. |

So the answer to the plan's "trigger *or* application guard" is **both**.
The ORM guard is cheap and also protects the test database. The trigger is
the real protection for every client that isn't a superuser. The hash
chain is what makes the log *tamper-evident* rather than only
*tamper-resistant*.

`scripts/tamper_demo.py --postgres` shows the full story. It gets past the
trigger the way only a superuser can
(`SET LOCAL session_replication_role = replica`), changes one entry, and
`verify` names that exact entry.

## Options considered

1. **Application guard only.** Rejected: it doesn't cover any client other
   than the gateway (psql, another service, a migration script).
2. **Trigger only.** Rejected: SQLite tests would have no guard at all, and
   the application would only find out about a mistaken update when
   Postgres raised.
3. **Revoke UPDATE/DELETE from the gateway's DB role.** This would be
   the strongest option without a trigger. It wasn't chosen *yet* because
   the Docker Compose setup runs the gateway as the `postgres` superuser,
   and privileges don't apply to superusers. Revisit in module 10, when
   the deployment gets a dedicated non-superuser role (LIMITATIONS.md L7-6).
4. **Write-once storage outside Postgres** (WORM bucket, external
   timestamping service). Real-world best practice for *tail* protection
   (see below), but out of scope for a single-node student deployment.

## Consequences

- No code path in the gateway can update or delete an entry. Retention
  (pruning old entries) is therefore not implemented: deleting the oldest
  entries would also break verification from the genesis hash unless a
  signed checkpoint were recorded first (LIMITATIONS.md L7-4).
- The hash chain can't tell when entries are deleted **from the end**:
  what's left is still a valid chain. `verify` returns `entry_count` and
  `head_hash` so they can be recorded elsewhere and compared on the next
  run (LIMITATIONS.md L7-2).
- Hashing each entry needs the previous entry's hash, so entries are
  chained one at a time by a single background writer, under a Postgres
  advisory lock so several gateway processes can't fork the chain. This is
  the audit log's throughput ceiling (LIMITATIONS.md L7-3).
- The hash covers a canonical text form of every column (UTC timestamps,
  cost to 6 decimal places, sorted JSON keys), so values that change
  formatting on the way through Postgres (JSONB, `numeric`, `timestamptz`)
  still hash the same when `verify` reads them back. This is tested against
  real Postgres in `tests/test_audit_postgres.py`.
