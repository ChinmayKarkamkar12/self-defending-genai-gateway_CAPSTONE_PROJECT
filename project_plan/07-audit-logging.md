# Module 7: Tamper-Evident Audit Logging

**Depends on:** Module 1 (repo), Module 2 (pipeline), Module 3 (cost data), Module 4 (redaction metadata), Module 5 (threat scores), Module 6 (actions taken) — this module's whole job is to record what the others decided
**Feeds into:** Module 8 (dashboard's log viewer and compliance export)

## 1. Purpose & scope

Record every request through the gateway as an immutable, tamper-evident log entry, and expose a query API for the dashboard. This is the module that turns "we have logs" into "we have logs a court or auditor would trust."

**In scope:** hash-chained log storage, structured log entries, query API, retention policy.
**Out of scope:** the dashboard UI that displays them (module 8).

## 2. Data model

```
AuditLogEntry   (Postgres, append-only — no UPDATE or DELETE permitted at the application layer)
  id: uuid (pk)
  sequence_number: bigint (unique, monotonically increasing)
  timestamp: timestamp
  request_id: uuid
  team_id: uuid
  api_key_id: uuid
  model: str
  redaction_summary: jsonb     # entity type -> count, from module 4, NEVER raw values
  threat_score: jsonb           # from module 5
  action_taken: str              # from module 6
  cost_usd: numeric(10,6)       # from module 3
  latency_ms: int
  entry_hash: str (sha256)      # hash of this entry's own content
  prev_hash: str (sha256)       # hash of the previous entry — this is the chain
```

## 3. Hash chaining mechanism

This is the concrete "tamper-evident" implementation — keep it simple and explainable:

```python
def compute_entry_hash(entry_fields: dict, prev_hash: str) -> str:
    canonical = json.dumps(entry_fields, sort_keys=True)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()
```

Each new entry's `prev_hash` is the previous entry's `entry_hash`. A `GENESIS_HASH` constant (e.g. 64 zeros) seeds the first entry. Any modification to a past entry's fields breaks its own hash *and* every subsequent entry's chain — this is the property to demonstrate in your faculty presentation: show a script that tampers with one row and verifies the chain detects it.

## 4. Write path

Logging must **never block the response to the client** — write path:
1. The pipeline's final step assembles the log entry from `ctx.metadata` (accumulated by every earlier stage)
2. Push it onto an async queue (an `asyncio.Queue` is enough for the demo scale; note in the README that a real production system would use a durable queue like Redis Streams or Kafka here — call this out as a documented scaling limitation, don't over-build it for a student deployment target)
3. A background worker consumes the queue, computes the hash chain sequentially (this must be single-threaded/serialized, since each hash depends on the previous one — document this as the throughput bottleneck and why it's an acceptable trade-off at demo scale)
4. Writes to Postgres

## 5. Verification tool

Write `app/core/audit/verify.py` — a standalone function/script that walks the full `AuditLogEntry` table in sequence order, recomputes each hash, and reports the first entry (if any) where the stored hash doesn't match. Expose this as an admin endpoint too, since "prove the log hasn't been tampered with" on demand is a genuinely good demo moment.

## 6. API contract

| Endpoint | Purpose |
|---|---|
| `GET /v1/admin/logs?team_id=&from=&to=&action=` | paginated log query for the dashboard |
| `GET /v1/admin/logs/verify` | runs the hash-chain verification, returns `{valid: bool, first_broken_entry: id \| null}` |
| `GET /v1/admin/logs/export?format=csv` | compliance export |

## 7. Implementation tasks

1. [ ] Add `AuditLogEntry` model + migration, with a Postgres-level trigger or application-level guard preventing UPDATE/DELETE on this table (document whichever approach you pick and why)
2. [ ] Write `app/core/audit/hashing.py` implementing `compute_entry_hash`
3. [ ] Write `app/core/audit/writer.py` — the async queue + background worker
4. [ ] Wire the final pipeline step in `app/core/pipeline.py` to enqueue log entries (extends module 2's pipeline, doesn't replace it)
5. [ ] Write `app/core/audit/verify.py`
6. [ ] Write the three admin endpoints above, including CSV export
7. [ ] Write a small demo script `scripts/tamper_demo.py` that manually corrupts one row in a test database and shows `verify()` catching it — useful for the faculty presentation

## 8. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_hashing.py::test_hash_deterministic` | Unit | same input fields always produce the same hash |
| `test_hashing.py::test_chain_links_correctly` | Unit | entry N's `prev_hash` equals entry N-1's `entry_hash` |
| `test_verify.py::test_detects_tampered_entry` | Unit — **the headline test, don't skip** | manually mutate one field of a stored entry, assert `verify()` flags it and correctly identifies which entry broke the chain |
| `test_verify.py::test_valid_chain_passes` | Unit | an untouched chain of N entries verifies clean |
| `test_writer.py::test_logging_does_not_block_response` | Integration | measure that the client response returns before the log write completes (assert on ordering/timing, not just that both eventually happen) |
| `test_writer.py::test_no_log_entries_lost_under_load` | Integration | fire many concurrent requests, assert the final log count matches the request count exactly (catches queue/race issues) |
| `test_redaction_summary.py::test_no_raw_pii_in_log_entry` | Unit — **security-critical** | assert no `AuditLogEntry` field contains a raw value matching the test PII used in module 4's fixtures |
| `test_admin_logs_api.py::test_query_filters_work` | Integration | filtering by team/date/action returns correct subset |

## 9. Definition of done

- [ ] The tamper demo script visibly catches a corrupted entry
- [ ] No PII leaks into logs — verified by test, not assumption
- [ ] Logging doesn't add meaningful latency to the client-facing response
- [ ] No entries lost under concurrent load
- [ ] All tests pass; `ruff check` clean
