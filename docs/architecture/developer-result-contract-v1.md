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

Read-only schema and policy inspection was performed against the configured Supabase project on 2026-10-27. These tables are candidates to map, not blanket approval to reuse without checking constraints, RLS, grants, and write paths.

| Concern | Existing table(s) | What they can support | Important limitation to verify |
|---|---|---|---|
| Watch target / asset hint | `dw_watchlist`, `dw_watch_aliases` | Tenant-scoped target values, kind, value hash, labels, severity, aliases | A watchlist row does not prove a scan, worker claim, or durable device identity |
| Current finding | `dw_findings`, `dw_alerts` | Existing matched values, source references, collection timestamps, alert/remediation status | Findings are not a complete ledger of all attempted tasks or unavailable sources |
| Source-level health | `dw_sources`, `dw_source_health_events` | Registered source configuration and source-level health observations | Source health is not evidence that a particular tenant target was checked |
| Onion probe evidence | `dw_onion_probe_evidence` | Per-seed probe metadata, route verification flag, response hash, outcome | It is onion-seed-level evidence, not a generic target-specific service receipt |
| Generic asynchronous request | `service_requests` | Request status, processing state, attempts, lock/start/completion times, failure code, JSON result | It binds through `organization_id`, not a direct `tenant_id`; worker resolves the organization's tenant. Do not collapse organization and tenant identity |
| Investigation session/event/evidence | `investigation_sessions`, `investigation_events`, `investigation_evidence`, `investigation_operations` | Existing session-like records, event payloads, operation authorization metadata, evidence hashes and collectors | Current observed RLS policies for sessions/events/evidence are tenant-scoped SELECT policies for `authenticated`; no corresponding authenticated INSERT policy appeared in the inspected policy set. A service-role writer and explicit tenant checks would be required unless another verified write path is found |
| Trust evidence and verification | `trust_evidence`, `trust_evidence_verification_events` | Content/evidence hashes, signatures and signer key IDs, verifier metadata, verification state/history | Current member-read policies allow rows with `tenant_id IS NULL` or tenant membership. Do not treat that policy alone as sufficient tenant-specific result authorization. Subject binding, signing algorithm, immutability, grants, and intended writers must be checked before linking DW results |

## Confirmed request and finding shape

The inspected `service_requests` columns include `organization_id`, `requester_user_id`, `service_key`, `target`, `target_type`, `status`, `processing_state`, `attempts`, `locked_until`, `started_at`, `completed_at`, `failure_code`, and JSONB `result`. There is no direct `tenant_id` column on this request table in the inspected schema. The worker resolves `organization_id` through `customer_organizations` before executing the scan.

The inspected `dw_findings` shape includes a numeric finding ID, `source_id`, `content_hash`, `kind`, `matched_value`, optional `source_url`, `tenant_id`, optional `watchlist_id`, `web_layer`, `access_mode`, and `collected_at`. Finding references therefore need an explicit mapping; the result contract's string IDs are transport identifiers, not permission to fabricate or silently coerce database records.

The current request API already creates a queued `dark_web_monitoring` request and exposes authenticated request/result reads. The worker stores source status arrays, unavailable reasons, findings, and evidence inside the request's JSON result. That is useful provenance, but it is not yet a dedicated append-only per-source attempt ledger or a signed coverage receipt.

## Gaps to resolve before persistence design

The inspected schema did not identify an obviously dedicated, generic per-service task receipt table that captures all of the following together:

- Result Session and tenant/asset binding.
- Service/task identity and declared scope.
- Attempt start/end times and lease identity.
- Per-source outcome, retry/idempotency identity, and explicit failure reason.
- Parser/collector version and evidence references.
- Coverage decision inputs and a replay cursor/event sequence.
- Delivery state, consumer cursor, retry count, and dead-letter/reconciliation state.

This is a gap hypothesis from inspected tables and columns, not proof that no equivalent path exists in code or another schema. Before adding tables, trace current worker writes, RPCs, grants, and actual relationships.

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
