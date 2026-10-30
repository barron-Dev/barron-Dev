# CSA migration and catalogue reconciliation — 2026-10-30

## Scope and safety

Read-only comparison of the live Supabase migration ledger/schema with checked-in repository sources. No production SQL was executed beyond SELECT/catalog inspection. This document is an engineering reconciliation record, not authorization to replay or baseline migrations.

## Live migration ledger

The live `supabase_migrations.schema_migrations` ledger contains seven CSA-related records:

| Live version | Live name | Repository source candidate | Finding |
|---|---|---|---|
| 20260916021844 | 027_compliance | `sql/027_compliance.sql` | Strong match: base tables, RLS, grants and initial control seed |
| 20260916022425 | compliance_control_library | `sql/028_compliance_control_library.sql` | Strong content match |
| 20260916022759 | compliance_catalog_seed | Seed INSERT block is present in `sql/027_compliance.sql`; no separate source file | Content candidate found, but separate ledger event's exact SQL/checksum is not independently recoverable from repository |
| 20260916022851 | compliance_hardening | `sql/026_compliance_hardening.sql` | Strong content match, version/name differs |
| 20260916022915 | compliance_security_hardening | `sql/027_compliance_security_hardening.sql` | Strong content match |
| 20260916023433 | compliance_snapshot_verification | `sql/028_compliance_verification.sql` | Strong content match |
| 20260916023455 | compliance_signing_rpc_hardening | `sql/029_compliance_signing_rpc_hardening.sql` | Strong content match for its historical one-argument `get_signing_key(text)` grant/revoke statement; compare against current live overloads before replay |

The seven ledger names are not enough to prove byte-for-byte source equivalence. The historical migration SQL and checksums are not stored alongside these records in the current repository layout. The source candidate mapping must not be used to replay these scripts.

## Seed provenance correction

The initial investigation described `compliance_catalog_seed` as having no source candidate. That was too broad. The checked-in `sql/027_compliance.sql` contains an explicit 11-row `INSERT INTO public.compliance_controls` seed block, including the two HIPAA controls `164.308(a)(1)` and `164.312(b)`.

This explains where the original seed content is represented in source, but it does not establish that the separate live `compliance_catalog_seed` migration executed exactly that same block or establish its checksum. Preserve that distinction until the original migration artifact or deployment log is recovered.

## Additional legacy SQL files and live-schema comparison

- `sql/029_compliance_public_key_verification.sql` is a separate legacy script and must not be assumed to represent the live two-argument public-key RPC. The live function signature was inspected as `get_signing_public_key(p_kid text, p_purpose text)`; inspect all live overloads and key lifecycle checks before any replay or replacement.
- `sql/029_compliance_signing_rpc_hardening.sql` revokes/grants the historical one-argument `get_signing_key(text)`. Live Supabase now exposes only the inspected two-argument overloads. Both live functions enforce the purpose allowlist and select only `active=true` keys with matching purpose; the private key is retrieved from Vault through `vault_secret_id`, and the public key is read from `public_pem`. The `signing_keys` table has `active` and `retired_at` but no explicit `not_before`/expiry columns. Both RPCs are SECURITY DEFINER and the inspected routine grants are limited to postgres/service_role; RLS denies client access. This confirms the current signing boundary but does not prove the full key-rotation lifecycle.
- `sql/030_compliance_freshness.sql` aligns with observed live fields `compliance_control_status.freshness_status`, `compliance_control_status.evidence_valid_until`, and `compliance_collection_results.valid_until`.
- `sql/030_compliance_evidence_freshness.sql` proposes additional `freshness_window_seconds` and `stale` fields that were not present in the inspected live columns. Do not treat both 030 files as one deployed migration.
- `sql/031_compliance_full_platform.sql` is not represented by the seven CSA ledger rows. Its principal tables (`audit_engagements`, `auditor_access`, `evidence_items`, `control_owners`, `control_exceptions`, `remediation_tasks`, `vendors`, `trust_center`) were absent in the inspected live schema. Treat this file as unapplied/source-only until independently reconciled.
- `sql/060_zk_compliance.sql` is outside the seven CSA ledger records and is not part of this reconciliation.

## Control catalogue

Live `public.compliance_controls`: 30 rows across seven frameworks. Twenty-eight rows have `stable_id`; two HIPAA rows have NULL `stable_id`:

- HIPAA `164.308(a)(1)`, “Security management process”
- HIPAA `164.312(b)`, “Audit controls”

The Python reference catalogue contained 28 entries and omitted exactly those two controls. The CSA branch adds deterministic application IDs following the existing HIPAA convention:

- `hipaa.164.308.a.1`
- `hipaa.164.312.b`

These are source-catalogue identifiers only. No production rows were changed and no SQL migration is included to backfill the live `stable_id` values. A future migration must be reviewed against the actual unique constraints, framework/code identity, and tenant/control references before it is applied.

## Current blockers

1. Recover the exact historical SQL/checksum or deployment artifact for the separate `compliance_catalog_seed` ledger event; the 11-row seed block in `027_compliance.sql` is a source candidate, not proof of the separate event's exact payload.
2. Reconcile all live `get_signing_key` and `get_signing_public_key` overloads, purpose checks, grants, key status and validity windows with the legacy signing scripts.
3. Confirm the exact deployed freshness migration and keep the competing 030 scripts distinct.
4. Keep 031 unapplied until its full DDL, grants, RLS, function ownership, and code dependencies are reviewed and migration source is placed under a single canonical migration convention.
5. Add a forward-only stable-ID backfill migration only after the above catalogue mapping is approved and tested against live foreign-key references.

## Release decision

No production migration, deployment, merge, credential change, or external customer probe was performed. Migration-history reconciliation remains open.


## Stable-ID backfill constraints and references

Live schema inspection found:
- `compliance_controls` has primary key `id` and unique `(framework, control_code)`.
- `compliance_controls_stable_id_uidx` is a partial unique index on `stable_id` where non-NULL.
- The two target HIPAA rows are the only NULL stable IDs in the inspected catalogue; no duplicate non-NULL stable IDs were returned.
- Four live tables reference `compliance_controls(id)`: `compliance_attestations`, `compliance_collection_results`, `compliance_control_status`, and `compliance_evidence`.

A future backfill can update only the two rows selected by the exact `framework='hipaa'` and `control_code` values, preserving primary keys and all existing foreign-key relationships. It must assert exactly two target rows and no stable-ID conflicts before updating, then assert zero remaining NULL stable IDs and verify the partial unique index. Do not recreate controls or rewrite foreign keys.
