# CSA migration and catalogue reconciliation — 2026-10-30

## Scope and safety

Read-only comparison of the live Supabase migration ledger/schema with checked-in repository sources. No production DDL or data changes were executed. The live ledger's `statements` array preserves the SQL payload for each migration; SHA-256 values below were computed over `array_to_string(statements, E'\\n')`. These records are the authoritative recovery source for the executed payloads. Do not replay historical statements.

## Authoritative live migration payloads

The seven CSA-related ledger rows each contain one preserved SQL statement. Payload checksums:

| Live version | Live name | Bytes | SHA-256 |
|---|---|---:|---|
| 20260916021844 | 027_compliance | 7,420 | `ab3fb74481c7165c7d9de9dd8cbe59c92158ceb1ae0f871c5b8a4e2fd93e9ec7` |
| 20260916022425 | compliance_control_library | 7,687 | `a66723c875c9d43af37b96a03a886c5cf48cfba5617f43751e093615169de021` |
| 20260916022759 | compliance_catalog_seed | 4,050 | `fefc1df2df30f4c9a6ba4855d5e88236e3bb4e175f571ed487f3750ba43ce296` |
| 20260916022851 | compliance_hardening | 3,639 | `742919a92bfcb5d0167f58fd667b6b4ca70fab7e3bfd39ee45f1cb130713a0f9` |
| 20260916022915 | compliance_security_hardening | 171 | `98c1542f8d947caf09a8cf600ddf23121687f50fb11b2ffa87e11bf3ccccb849` |
| 20260916023433 | compliance_snapshot_verification | 2,158 | `edba013cdb62b2e006cd1039182badcad2349b71d2e315cfe549133cc6797682` |
| 20260916023455 | compliance_signing_rpc_hardening | 157 | `42d0a46a6718ab696d5109e5422ce8520df09794c58b094921c12d2219d24c13` |

These checksums identify the preserved live payloads. They do not prove that a checked-in SQL file is byte-identical; that comparison must be made separately.

## Source reconciliation corrections

- `20260916021844 / 027_compliance`: the live payload is the base compliance schema and initial 11-row seed. The checked-in `sql/027_compliance.sql` is a strong content candidate, but byte identity has not been established.
- `20260916022425 / compliance_control_library`: **this is the live source of the `compliance_controls.stable_id` column and `compliance_controls_stable_id_uidx` partial unique index.** Its preserved SQL also creates the framework/control-status/evidence-snapshot/attestation/policy-document structures and expands framework support. The checked-in `sql/028_compliance_control_library.sql` does not reproduce this full payload and is not an authoritative copy of the executed migration.
- `20260916022759 / compliance_catalog_seed`: the preserved live statement is a separate 27-row seed using `stable_id`, including SOC 2, ISO, GDPR, HIPAA, PCI DSS, UAE PDPL and Nigeria NDPA entries. It is **not** the 11-row seed block in `sql/027_compliance.sql`. The old source-candidate description was incorrect; recover this payload from the live ledger into a clearly marked archival source before declaring source restoration complete.
- `20260916022851 / compliance_hardening`: checked-in `sql/026_compliance_hardening.sql` remains a content candidate only; byte identity has not been established.
- `20260916022915 / compliance_security_hardening`: compare the 171-byte live statement with the checked-in candidate before treating it as restored.
- `20260916023433 / compliance_snapshot_verification`: checked-in `sql/028_compliance_verification.sql` remains a content candidate only; byte identity has not been established.
- `20260916023455 / compliance_signing_rpc_hardening`: live ledger statement revokes/grants the historical one-argument `get_signing_key(text)`. Current live RPC is two-argument; the old file must not be replayed.

## Live signing boundary

Read-only inspection of live PostgreSQL confirms only these public overloads:
- `get_signing_key(text,text)`
- `get_signing_public_key(text,text)`

Both enforce the purpose allowlist `COMMAND`, `AI_ENVELOPE`, `FEDERATION`, `COMPLIANCE` and select only active keys matching both key ID and purpose. Private material is fetched from Vault using `vault_secret_id`; public material comes from `public_pem`. Both are SECURITY DEFINER with constrained search paths. Earlier grant inspection found execution limited to postgres/service_role and RLS prevents client table access. The live `signing_keys` table has `active` and `retired_at`, but no explicit `not_before`/expiry fields. This confirms the current selector boundary, not a complete key-rotation lifecycle.

## Freshness and full-platform scripts

- `sql/030_compliance_freshness.sql` aligns with observed live fields `compliance_control_status.freshness_status`, `compliance_control_status.evidence_valid_until`, and `compliance_collection_results.valid_until`; the exact live migration event introducing them still needs to be located in the full ledger.
- `sql/030_compliance_evidence_freshness.sql` proposes additional `freshness_window_seconds` and `stale` fields absent in the inspected live schema. Do not combine the competing 030 scripts.
- `sql/031_compliance_full_platform.sql` is not represented by the seven CSA ledger rows. Its principal tables (`audit_engagements`, `auditor_access`, `evidence_items`, `control_owners`, `control_exceptions`, `remediation_tasks`, `vendors`, `trust_center`) were absent in the inspected live schema. Treat as source-only/unapplied pending complete DDL, grants, RLS, function ownership and dependency review.
- `sql/060_zk_compliance.sql` is outside this seven-row reconciliation.

## Live control catalogue and safe backfill

Live `public.compliance_controls` has 30 rows across seven frameworks. Twenty-eight have `stable_id`; two HIPAA rows are NULL:
- `164.308(a)(1)` — Security management process
- `164.312(b)` — Audit controls

The application catalogue now includes `hipaa.164.308.a.1` and `hipaa.164.312.b`. No production rows were changed.

Live schema inspection:
- Primary key: `id`; unique constraint: `(framework, control_code)`.
- Partial unique index: `compliance_controls_stable_id_uidx` on non-NULL `stable_id`.
- Four referencing tables: `compliance_attestations`, `compliance_collection_results`, `compliance_control_status`, and `compliance_evidence`, all referencing `compliance_controls(id)`.

The origin of the stable-ID column/index is now identified as live migration `20260916022425`. The remaining catalogue task is a forward-only, narrowly scoped backfill of exactly the two HIPAA rows. It must assert exactly two targets, no stable-ID conflicts, preserve all primary keys/FKs, then assert zero remaining NULL stable IDs and validate the partial unique index.

## Remaining release gates

1. Restore the exact live SQL payloads into clearly labelled archival source files (not replayable migrations) and compare each against checked-in candidates.
2. Locate the live ledger event that introduced the freshness fields and reconcile the competing 030 scripts.
3. Reconcile key status/rotation lifecycle beyond the current active/purpose selector.
4. Prepare and test the forward-only two-row HIPAA stable-ID backfill; do not apply it until separately approved.
5. Add trusted receipt persistence and tenant-isolated APIs.
6. Implement one authorized, isolated effectiveness probe with bounded scope and verified cleanup.
7. Complete customer and developer frontend workflows, then obtain passing current-head CI and authenticated tenant/signature end-to-end proof.

## Release decision

No production migration, deployment, merge, credential change, or external customer probe was performed. The live ledger has materially reduced migration-provenance uncertainty, but source restoration, forward migration review, receipt persistence, real probe execution and end-to-end proof remain open.
