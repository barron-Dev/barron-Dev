# DW class-level trust controls — preview acceptance plan

This work is preview-branch only. It does not apply migrations, deploy services, enable collectors, or write production data.

## Finding classes (root cause, not isolated instances)

| Class | Root cause | Structural control | Status |
|---|---|---|---|
| **DW-04 — caller-attested trust facts** | A caller can submit a boolean/status saying Tor routing, publisher identity, corroboration, provenance, or signature verification succeeded. The probe RPC is one instance; the evidence writer and canary/mirror paths share the same failure mode. | Replace success booleans with proof references; validate source/content/expiry/pin/anchor/evidence linkage inside one transaction; deny application-role writes to proof artifacts; lint function signatures before merge. | Legacy probe signature removed in preview migration. Trusted proof writers and end-to-end verification remain blocked. |
| **DW-POLICY-01 — evidence-policy drift** | Hand-maintained table lists and uniform grants silently omit new tables or grant mutable state to an application role. | Registry-driven grants/RLS/mutability, fail-closed table discovery, plus CI drift lint. Mutable OTS receipts are not treated as append-only logs, and direct application writes remain disabled until trusted writers exist. | Implemented in preview migrations; database execution tests pending. |
| **DW-OTS-01 — receipt presence mistaken for confirmation** | Existence or a caller-set `verified` flag is treated as proof, without explicit pending/confirmed/failure semantics. | Five-state OTS model; new receipts start pending; legacy confirmed claims are demoted to pending with `demoted_at`, `demoted_from_state`, and `demotion_reason` provenance; confirmed requires block height and verifier timestamp; finding visibility must join only confirmed receipt state. | State model drafted. Finding-view/customer-path integration remains blocked. |
| **DW-BASE-01 — migration base is not reproducible** | Migration filenames and status checks do not establish that the live DDL, ACLs, extensions, functions, and RLS match the preview assumptions. The prior OTS/TSA DDL was also malformed. | Repair DDL and reconcile the live schema into a reproducible disposable base before migration-ordering tests. | DDL repair and inventory documented; isolated schema snapshot and DB test run remain blocked. |
| **DW-FINDING-01 — evidence is not linked to customer findings** | Legacy `dw_findings` has no `evidence_seq`, and live has no `dw_verified_findings` view/table. OTS state therefore cannot yet gate the customer-visible finding path. | Introduce and wire an evidence-linked finding materializer/view, then test customer/API/history paths against all five OTS states. | Release blocker; deliberately not papered over with a synthetic view or guessed join. |

## Structural policies

- Evidence, proof, trust, health, fingerprint, embedding, credential, assignment, pin, observation, and telemetry tables must be listed in `dw_table_security_policy`; migrations abort when a table in these classes is unregistered or a registry row points to a missing table. The follow-on proof migration extends the assertion to proof artifacts.
- The existing PR #76 evidence migration had a malformed OTS/TSA table-definition block (unterminated hash check and duplicated columns). The branch repairs the DDL and requires both evidence and anchor references for each OTS receipt.
- The migration derives RLS, grants, and append-only triggers from that registry. OTS and TSA receipts are explicitly mutable state machines, not append-only event logs.
- The initial caller-attestation lint is warning-only. It scans all PostgreSQL function signatures (not only SECURITY DEFINER functions) because invoker RPCs can still trust forged boolean claims. It also flags evidence/proof tables created without a registry row. **Target date to make the lint blocking: 2026-10-31.** It must be blocking before any future trust RPC is eligible to merge; until then, DW-04 recurrence is not prevented in merged code.
- The legacy boolean-parameter probe RPC is revoked from application roles and dropped by the proof-bound migration. The replacement accepts proof IDs and validates source, request URL, content hash, publisher pin/host match, evidence sequence, corroboration record, and confirmed OTS receipt inside the transaction.
- Evidence, receipt, anchor, source-health, and proof artifact tables are read-only to `service_role` on purpose. Writes must flow through a trusted verifier/writer path. Until those writers are implemented and independently tested, the proof-bound success path fails closed. Because the proof tables have no trusted writer and OTS has no verifier, the verified-finding path is **structurally guaranteed to produce zero verified findings** in this branch; this is not merely an untested integration. Do not manually seed proof rows or claim live verification.

## Required test matrix

1. **Registry completeness:** introduce a temporary `public.dw_test_evidence_fixture` table without a registry row; migration preflight must fail. Add a row and verify the policy is applied.
2. **Registry staleness:** add a registry row for a missing table; migration must fail.
3. **Privilege negative tests:** iterate every registry row; INSERT/UPDATE/DELETE as `anon` and `authenticated` must be rejected. Also assert the exact intended `service_role` grants for each row.
4. **Append-only enforcement:** for every `append_only=true` table, UPDATE and DELETE as `service_role` must fail; INSERT must succeed in a disposable fixture transaction.
5. **OTS state transitions:** test `pending -> confirmed`, `pending -> failed`, `pending -> expired`, and `pending -> invalid`; only `confirmed` with a block height and matching evidence/anchor may satisfy the verified-finding evidence join. Pending is unresolved, not clean. Failed/invalid/expired/pending must be excluded.
6. **Atomic proof rejection:** each invalid/missing Tor-route proof, publisher proof, corroboration anchor, or source-mismatched evidence reference must reject within a transaction and leave no probe attempt, receipt, or finding rows.
7. **Tenant isolation:** cross-tenant entity, evidence, anchor, and finding joins must be denied; verify both read and write paths.
8. **Migration ordering/base:** run against a disposable database initialized from a documented snapshot of the live schema plus the known-good migrations before PR #76. A PR #76-only empty database is not evidence of compatibility. Until the Block-2 reconciliation table identifies that base, report this test as blocked rather than passed.
9. **Verified-finding propagation:** the live schema currently has `dw_findings` and `dw_alerts`, but no `dw_verified_findings` view/table, and legacy `dw_findings` lacks an `evidence_seq` column. Therefore the OTS exclusion is not yet wired to the customer finding materializer. This remains a release blocker until the evidence-backed finding model and customer/API path are connected and tested.

## Next gate and release hold

The next gate is **the disposable schema snapshot that demonstrably reproduces live production**—not another classification block and not proof writers. The reconciliation document above is an inventory, not a runnable replica. Capture schema-only DDL with `pg_dump`, apply it to a fresh disposable database, and compare functions, ACLs, RLS policies, extensions, and triggers against live before marking the base reproducible. Do not use production credentials for tests or apply preview migrations to production.

After the snapshot gate passes, implement and test in this order: (1) trusted OTS verifier, (2) trusted proof writers, (3) evidence-linked `dw_verified_findings` view/materializer and customer/API/history propagation. Permission, ordering, and atomic-rejection tests must run against that reproduced base.

Release picture: serving API remains offline; schema reproducibility remains unproven; trust-layer structure is advanced but writers are absent; verified findings remain blocked. This branch does not address the serving API.

No production migration or deployment until the schema snapshot is reproducible and registry tests, proof-bound RPC tests, OTS state propagation, tenant isolation, and full authenticated end-to-end evidence tests pass. A Vercel deployment status alone is not backend or end-to-end proof.
