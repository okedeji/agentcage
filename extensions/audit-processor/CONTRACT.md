# Audit Processor — Kotlin

Consumes exported audit logs and stores them in a queryable format.

## What this service does

- Reads audit log exports (signed JSON) from the agentcage orchestrator
- Validates chain integrity on ingestion (verify HMAC signatures and chain links)
- Stores entries in a queryable format optimized for search, filtering, and timeline views
- Supports concurrent processing across thousands of cage audit streams

## Integration points

### Input: Audit log exports

The orchestrator exports audit logs as signed JSON via the `audit.Export()` function. The export envelope:

```json
{
  "cage_id": "cage-456",
  "assessment_id": "assessment-123",
  "entries": [
    {
      "id": "entry-1",
      "sequence": 1,
      "type": "cage_provisioned",
      "timestamp": "2026-03-28T10:00:00Z",
      "data": {},
      "key_version": "v1",
      "signature": "base64...",
      "previous_hash": "base64..."
    }
  ],
  "digest": {
    "chain_head_hash": "base64...",
    "entry_count": 42,
    "signature": "base64..."
  },
  "exported_at": "2026-03-28T10:35:00Z"
}
```

### Output: Postgres

Writes to the `audit_entries` table (TimescaleDB hypertable). Schema in `migrations/004_audit_entries.sql`.

### Entry types

24 entry types defined in `internal/audit/types.go`:

cage_provisioned, cage_started, cage_paused, cage_resumed, cage_torn_down,
policy_applied, policy_removed, egress_allowed, egress_blocked,
payload_allowed, payload_blocked, payload_held, finding_emitted,
finding_validated, finding_rejected, tripwire_fired,
intervention_requested, intervention_resolved, identity_issued,
identity_revoked, secret_fetched, secret_revoked, llm_request, llm_response

## Tech stack

- Kotlin with coroutines for concurrent processing
- Postgres/TimescaleDB for storage
- JSON parsing with kotlinx.serialization

## Build

```
cd services/audit-processor
./gradlew build
./gradlew test
```
