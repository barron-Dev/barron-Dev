# Block 2 — DW live-schema reconciliation

**Purpose:** define the disposable PostgreSQL base required to validate PR #76 and the class-level trust-control migrations. This is an inventory, not a production change. Observations below are from read-only production inspection on 2026-10-23, with a targeted table-presence recheck on 2026-10-24.

## Reconciliation table

| Area | Last verified live state | Preview migration consequence | Status |
|---|---|---|---|
| Discovery queue | `dw_source_discovery_queue` exists. Queue lease/claim/complete/quarantine migrations are already recorded in the live migration ledger. The last measured backlog was 26,062 rows, all `deferred`, with zero active leases. | Do not replay PR #73 queue migrations blindly. Base the preview DB on the existing queue schema and current RPC definitions. | Present; reconcile exact DDL/ACL |
| Onion inventory | `dw_onion_seeds` exists; last measured count was 1,023. Last measured monitoring-enabled count was 0. | PR #76 tables and proof-bound RPC must reference this existing table and preserve candidate-vs-verified separation. | Present |
| Probe evidence | `dw_onion_probe_evidence` exists; last measured count was 0. Existing `dw_record_onion_probe_result` accepts caller-supplied boolean claims for Tor route, publisher proof, corroboration, and provenance. Its execute ACL was limited to `postgres` and `service_role`. | Preview migration revokes/drops the legacy signature and replaces it with artifact-reference validation. The production function is not changed by this branch. | Present; trust gap identified |
| Source health events | `dw_source_health_events` exists; last measured count was 0. | Registry must lock direct app writes and let only trusted RPCs write observations. | Present |
| PR #76 trust tables | The targeted live check found none of: `dw_client_auth_credentials`, `dw_circuit_assignments`, `dw_mirror_integrity`, `dw_content_fingerprints`, `dw_publisher_key_pins`, `dw_content_embeddings`, `dw_source_anomaly_events`, `dw_descriptor_health`, `dw_trust_honeypot_observations`, `dw_trust_canary_events`. | The trust foundation is not applied in production; validate its dependency chain only in the disposable preview database. | Absent in live |
| PR #76 evidence-processing tables | The targeted live check found none of: `dw_evidence_log`, `dw_evidence_ots_receipts`, `dw_evidence_tsa_receipts`, `dw_merkle_anchors`, `dw_sanitized_content`, `dw_entities`, `dw_entity_aliases`, `dw_entity_links`, `dw_entity_mentions`, `dw_discovery_job_runs`, `dw_discovery_dead_letters`, `dw_source_health`. | Repair the malformed OTS/TSA DDL first; then test registry, state machine, and proof-bound RPC in migration order. | Absent in live |
| Proof-bound tables | `dw_tor_route_proofs`, `dw_publisher_proofs`, and `dw_corroboration_proofs` do not exist in live. | New tables are preview-only and deliberately read-only to `service_role`; no trusted proof writer exists yet, so success must fail closed. | Absent in live |
| Finding path | Live has `dw_findings` and `dw_alerts`; it has no `dw_verified_findings`. Legacy `dw_findings` has no `evidence_seq` column. | OTS state exclusion cannot honestly be called wired until an evidence-linked finding materializer/view and customer/API path are implemented. | Release blocker |
| Extensions | Last verified: `pg_trgm` and `pgcrypto` are in schema `extensions`; `vector` is in `public`. | Preserve qualified extension operators/functions and verify extension placement in the disposable DB. | Known; recheck in test base |
| Production migration ledger | Queue foundation versions observed: `20261021064731` lease columns, `20261021064748` claim/complete RPC, `20261021070050` operational-table lockdown, `20261021081258` backlog quarantine forward. PR #76 migration versions are absent. | Never infer that a migration is applied from a filename, branch, or green Vercel status. | Reconciled at ledger level |

## Required disposable base

The correct test base is **a reproducible schema snapshot of live production immediately before PR #76**, plus the already-applied migration chain that establishes the existing queue, seed, probe-evidence, source-health, extension, function, ACL, and RLS state.

A migration ledger and table-presence list are not a complete schema snapshot. The following are still required before migration-ordering tests can be marked passed:

- [ ] Capture DDL for all relevant tables, indexes, constraints, sequences, functions, triggers, grants, and RLS policies.
- [ ] Record exact extension versions and schemas.
- [ ] Recreate that snapshot in an isolated disposable PostgreSQL database.
- [ ] Apply PR #76 migrations and these follow-on migrations in order.
- [ ] Run the negative privilege tests, OTS state tests, proof-rejection atomicity tests, tenant-isolation tests, and authenticated end-to-end evidence tests.
- [ ] Preserve test output and the exact base revision/schema fingerprint.

Until that reproducible base exists, migration-ordering and full database integration tests remain **BLOCKED**, not passed. No production migration, deployment, worker activation, or proof insertion was performed for this reconciliation.
