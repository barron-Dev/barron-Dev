# CSA migration and catalogue reconciliation — 2026-10-30

## Scope and safety

Read-only comparison of the live Supabase migration ledger/schema with checked-in repository sources. No production SQL was executed beyond SELECT/catalog inspection. This document is an engineering reconciliation record, not authorization to replay or baseline migrations.

## Live migration ledger

The live `supabase_migrations.schema_migrations` ledger contains these seven CSA-related records:

| Live version | Live name | Repository source candidate | Finding |
|---|---|---|---|
| 20260916021844 | 027_compliance | `sql/027_compliance.sql` | Strong filename/content match |
| 20260916022425 | compliance_control_library | `sql/028_compliance_control_library.sql` | Strong content match |
| 20260916022759 | compliance_catalog_seed | No standalone matching SQL file | Unresolved; do not assume `027_compliance.sql` is the complete deployed seed |
| 20260916022851 | compliance_hardening | `sql/026_compliance_hardening.sql` | Strong content match, version/name differs |
| 20260916022915 | compliance_security_hardening | `sql/027_compliance_security_hardening.sql` | Strong content match |
| 20260916023433 | compliance_snapshot_verification | `sql/028_compliance_verification.sql` | Strong content match |
| 20260916023455 | compliance_signing_rpc_hardening | `sql/029_compliance_signing_rpc_hardening.sql` | Strong content match |

The seven ledger names are not enough to prove byte-for-byte source equivalence. The historical migration SQL and checksums are not stored alongside these records in the current repository layout. The source candidate mapping must not be used to replay these scripts.

## Additional legacy SQL files and live-schema comparison

- `sql/029_compliance_public_key_verification.sql` defines a one-argument `get_signing_public_key(text)`. Live Supabase exposes `get_signing_public_key(p_kid text, p_purpose text)`. The legacy file is not safe to replay and is not a matching source of the current live function.
- `sql/030_compliance_freshness.sql` aligns with observed live fields `compliance_control_status.freshness_status`, `compliance_evidence.valid_from/valid_until`, and `compliance_collection_results.valid_until`.
- `sql/030_compliance_evidence_freshness.sql` proposes additional `freshness_window_seconds` and `stale` fields that were not present in the inspected live columns. Do not treat both 030 files as one deployed migration.
- `sql/031_compliance_full_platform.sql` is not represented by the seven CSA ledger rows. Its principal tables (`audit_engagements`, `auditor_access`, `evidence_items`, `control_owners`, `control_exceptions`, `remediation_tasks`, `vendors`, `trust_center`) were absent in the inspected live schema. Treat this file as unapplied/source-only until independently reconciled.
- `sql/060_zk_compliance.sql` is outside the seven CSA ledger records and is not part of this reconciliation.

## Control catalogue

Live `public.compliance_controls`: 30 rows across seven frameworks. Twenty-eight rows have `stable_id`; two HIPAA rows have NULL `stable_id`:

- HIPAA `164.308(a)(1)`, “Security management process”
- HIPAA `164.312(b)`, “Audit controls”

The Python reference catalogue contained 28 entries and omitted exactly those two controls. This branch adds deterministic IDs using the established existing HIPAA naming convention:

- `hipaa.164.308.a.1`
- `hipaa.164.312.b`

These are source-catalogue identifiers only. No production rows were changed and no SQL migration is included to backfill the live `stable_id` values. A future migration must be reviewed against the actual unique constraints, framework/code identity, and tenant/control references before it is applied.

## Current blockers

1. Recover the exact historical SQL/checksum for `compliance_catalog_seed`; confirm whether the seed is embedded in another deployed script or was run separately.
2. Recover/verify source for the live two-argument `get_signing_public_key` implementation; do not replay the legacy one-argument file.
3. Decide whether the second 030 file was ever applied; current live columns do not show all of its additions.
4. Keep 031 unapplied until its full DDL, grants, RLS, function ownership, and code dependencies are reviewed and migration source is placed under a single canonical migration convention.
5. Add a forward-only stable-ID backfill migration only after the above catalogue mapping is approved and tested against live foreign-key references.

## Release decision

No production migration, deployment, merge, credential change, or external customer probe was performed. Migration-history reconciliation remains open.
