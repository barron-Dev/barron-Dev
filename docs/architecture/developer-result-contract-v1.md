# Developer Result Contract v1 — storage and execution mapping

Status: implementation design for review. This document does not assert that Result Sessions, signed receipts, replay, or continuous delivery are live.

## Contract principles

- A result describes what was attempted and what evidence supports it; it is not merely a findings array.
- `no_match_in_completed_scope` is valid only when every declared task was attempted and completed successfully.
- `partial_coverage`, `blocked`, `failed`, and `unavailable` are not clean outcomes.
- Evidence provenance and verification state are separate from the finding's severity or an AI-generated summary.
- A content hash supports integrity checks but does not, by itself, authenticate the collector or source.
- A receipt is `unsigned` until a real signing and verification path is wired and tested.
- AI enrichment may suggest correlations; it cannot promote a result to `verified` without evidence and an authorized verifier.

## Current storage candidates observed in Supabase

The following existing tables were found in the configured Supabase project during a read-only schema inspection on 2026-10-26. They are candidates to map, not blanket approval to reuse without checking their constraints, RLS, grants, and write paths.

| Concern | Existing table(s) | What they can support | Important limitation to verify |
|---|---|---|---|
| Watch target / asset hint | `dw_watchlist`, `dw_watch_aliases` | Tenant-scoped target values, kind, value hash, labels, severity, aliases | A watchlist row does not prove a scan, worker claim, or durable device identity |
| Current finding | `dw_findings`, `dw_alerts` | Existing matched values, source references, collection timestamps, alert/remediation status | Findings are not a complete ledger of all attempted tasks or unavailable sources |
| Source-level health | `dw_sources`, `dw_source_health_events` | Registered source configuration and source-level health observations | Source health is not evidence that a particular tenant target was checked |
| Onion probe evidence | `dw_onion_probe_evidence` | Per-seed probe metadata, route verification flag, response hash, outcome | It is onion-seed-level evidence, not a generic target-specific service receipt |
| Generic asynchronous request | `service_requests` | Request status, processing state, attempts, lock/start/completion times, failure code, JSON result | It uses `organization_id`; do not equate it to `tenant_id` or reuse it for DW sessions until ownership, lifecycle, and worker semantics are verified |
| Investigation session/event/evidence | `investigation_sessions`, `investigation_events`, `investigation_evidence`, `investigation_operations` | Existing session-like records, event payloads, operation authorization metadata, evidence hashes and collectors | These tables have investigation/case/operation semantics; verify authorization model and retention before generalizing them into the developer Result Session |
| Trust evidence and verification | `trust_evidence`, `trust_evidence_verification_events` | Content/evidence hashes, signatures and signer key IDs, verifier metadata, verification state/history | Tenant and subject relationships, signing algorithms, immutability, grants, and intended writers must be checked before linking DW results |

## Gaps to resolve before persistence design

The schema inventory did not identify an obviously dedicated, generic per-service task receipt table that captures all of the following together:

- Result Session and tenant/asset binding.
- Service/task identity and declared scope.
- Attempt start/end times and lease identity.
- Per-source outcome, retry/idempotency identity, and explicit failure reason.
- Parser/collector version and evidence references.
- Coverage decision inputs and a replay cursor/event sequence.
- Delivery state, consumer cursor, retry count, and dead-letter/reconciliation state.

This is a gap hypothesis from table names and columns, not proof that no equivalent path exists in code or another schema. Before adding tables, trace current worker writes, RPCs, RLS policies, grants, and actual relationships.

## Safe implementation order

1. Keep the typed contract and its validation tests independent of production storage.
2. Trace the real DW request and collector path from authenticated API through queue/worker, source attempts, finding persistence, and evidence writing.
3. Determine whether existing session/event/evidence primitives can be reused without changing their established semantics or tenant boundaries.
4. If a gap remains, design the smallest additive migration and its least-privilege RPCs; validate constraints, RLS, grants, idempotency, lease fencing, and rollback in an isolated environment first.
5. Wire one supported DW flow end-to-end. Do not emit a result receipt until its underlying attempts and evidence can be read back and validated.
6. Add delivery bindings only after result persistence and replay semantics are stable.

## Explicit non-goals for this slice

- No production schema changes or data writes.
- No pairing endpoint or credential issuance yet.
- No claim of signed coverage receipts.
- No synthetic production results.
- No new source activation, worker activation, deployment, or Railway action.
