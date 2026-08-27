# Module 4: PII Redaction

**Depends on:** Module 1 (repo), Module 2 (pipeline hook interface, `pii_redaction_stage` stub)
**Feeds into:** Module 7 (audit log stores the redacted, not raw, prompt)
**Can be built in parallel with:** Module 3, Module 5

## 1. Purpose & scope

Implement the `pii_redaction_stage`: detect and mask sensitive data in the prompt before it's forwarded upstream, using Microsoft Presidio as the detection backbone plus custom rules for anything Presidio misses.

**In scope:** entity detection (names, emails, phone numbers, SSNs, credit cards, addresses), configurable redaction modes, per-team redaction policy.
**Out of scope:** scanning the LLM's *response* for leaked PII — that's part of the output-scan stage, tracked in module 5's file since it shares infrastructure with threat detection's output checks. This module only handles the outbound prompt.

## 2. Data model additions

```
RedactionPolicy   (Postgres — admin-configured)
  id: uuid (pk)
  team_id: uuid (fk)
  enabled_entities: jsonb   # e.g. ["EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", "PERSON"]
  mode: enum(mask, tokenize)
```

For `tokenize` mode, add a `RedactionVault` table mapping `token -> original_value`, encrypted at rest (use `cryptography`'s Fernet with a key from env config, not hardcoded). This lets a legitimate downstream process request the real value back via a separate authenticated endpoint — don't wire that endpoint up unless a real use case needs it; stub the table now so the schema doesn't need to change later.

```
RedactionVault
  token: str (pk)          # e.g. "[REDACTED_EMAIL_a1b2c3]"
  encrypted_value: bytes
  team_id: uuid
  created_at: timestamp
  expires_at: timestamp
```

## 3. Detection approach — two layers

1. **Presidio** (`presidio-analyzer` + `presidio-anonymizer`) — handles named entities: person names, locations, organizations, emails, phone numbers, IP addresses, and has good pre-built recognizers for many countries' ID formats.
2. **Custom regex layer** (`app/core/redaction/patterns.py`) — for anything Presidio's default recognizers handle poorly or that's domain-specific to this project's demo data: API key formats (`sk-...`, `AKIA...`), credit card Luhn-validated patterns, custom internal ID formats. Run this *after* Presidio and merge findings, de-duplicating overlapping spans.

## 4. Pipeline stage contract

`pii_redaction_stage.process(ctx)`:
1. Look up the team's `RedactionPolicy`
2. Run Presidio analyzer + custom regex layer on `ctx.request_body`'s prompt content, restricted to `enabled_entities`
3. Apply the configured `mode`:
   - `mask` → replace with `[REDACTED_<ENTITY_TYPE>]`
   - `tokenize` → replace with a unique token, write the mapping to `RedactionVault`
4. Return `MODIFY(new_payload)` with the redacted prompt, and attach `ctx.metadata["redaction_map"]` (entity type → count, no raw values) for the audit logger
5. Never let a raw detected value leak into `ctx.metadata` or logs — only counts and entity types

## 5. Implementation tasks

1. [ ] Add `RedactionPolicy` and `RedactionVault` models + migration
2. [ ] Install and configure `presidio-analyzer` + `presidio-anonymizer` (note: Presidio's analyzer needs a spaCy model — use `en_core_web_lg` or the smaller `en_core_web_sm` if resources are tight for the demo environment)
3. [ ] Write `app/core/redaction/patterns.py` with regex recognizers for API keys and Luhn-validated card numbers
4. [ ] Write `app/core/redaction/merge.py` to de-duplicate overlapping spans between Presidio and the regex layer
5. [ ] Write the real `pii_redaction_stage` replacing the module-2 stub, implementing both `mask` and `tokenize` modes
6. [ ] Write `app/core/redaction/vault.py` with Fernet encryption for tokenize mode
7. [ ] Write admin endpoints: `GET/PUT /v1/admin/redaction-policy/{team_id}`

## 6. Test plan

| Test | Type | What it verifies |
|---|---|---|
| `test_presidio_detection.py::test_detects_email_and_phone` | Unit | known test strings with an email and phone number are correctly flagged |
| `test_regex_patterns.py::test_detects_api_key_format` | Unit | a fake `sk-...`-style string is caught by the custom regex layer |
| `test_regex_patterns.py::test_credit_card_luhn_validation` | Unit | a Luhn-valid test card number (use a documented test number, never a real one) is flagged; a random 16-digit non-Luhn-valid number is not |
| `test_merge.py::test_overlapping_spans_deduplicated` | Unit | when Presidio and regex both flag overlapping text, only one redaction is applied |
| `test_redaction_stage.py::test_mask_mode_replaces_with_placeholder` | Unit | mask mode output contains no original PII substring |
| `test_redaction_stage.py::test_tokenize_mode_roundtrip` | Unit | tokenize mode produces a token, vault lookup returns the original decrypted value, no raw value appears in the token itself |
| `test_redaction_stage.py::test_metadata_never_contains_raw_values` | Unit — **security-critical, don't skip** | assert `ctx.metadata["redaction_map"]` contains only entity-type counts, never substrings of the original PII |
| `test_redaction_stage.py::test_disabled_entity_types_not_redacted` | Unit | if `enabled_entities` excludes `PERSON`, a name in the prompt passes through unredacted |

## 7. Definition of done

- [ ] A prompt containing an email, a phone number, and a fake API key comes out fully redacted in mask mode
- [ ] Tokenize mode round-trips correctly and the vault is encrypted at rest
- [ ] The security-critical metadata test passes — this is the one to double-check by hand, not just trust green CI
- [ ] All tests pass; `ruff check` clean
