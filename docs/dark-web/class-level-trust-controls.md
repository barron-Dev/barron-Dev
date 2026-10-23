# DW class-level trust controls — preview acceptance plan

This work is preview-branch only. It does not apply migrations, deploy services, enable collectors, or write production data.

## Structural policies

- Evidence-related tables must be listed in `dw_table_security_policy`; the migration aborts when a `dw_%evidence%` table is missing a policy or a registry row points to a missing table.
- The migration derives RLS, grants, and append-only triggers from that registry. OTS and TSA receipts are explicitly mutable state machines, not append-only event logs.
- The initial caller-attestation lint is warning-only. It scans all PostgreSQL function signatures (not only SECURITY DEFINER functions) because invoker RPCs can still trust forged boolean claims.

## Required test matrix

1. **Registry completeness:** introduce a temporary `public.dw_test_evidence_fixture` table without a registry row; migration preflight must fail. Add a row and verify the policy is applied.
2. **Registry staleness:** add a registry row for a missing table; migration must fail.
3. **Privilege negative tests:** iterate every registry row; INSERT/UPDATE/DELETE as `anon` and `authenticated` must be rejected. Also assert the exact intended `service_role` grants for each row.
4. **Append-only enforcement:** for every `append_only=true` table, UPDATE and DELETE as `service_role` must fail; INSERT must succeed in a disposable fixture transaction.
5. **OTS state transitions:** test `pending -> confirmed`, `pending -> failed`, `pending -> expired`, and `pending -> invalid`; only `confirmed` may satisfy the verified-finding evidence join. Pending is unresolved, not clean.
6. **Atomic proof rejection:** each invalid/missing Tor-route proof, publisher proof, corroboration anchor, or source-mismatched evidence reference must reject within a transaction and leave no probe attempt, receipt, or finding rows.
7. **Tenant isolation:** cross-tenant entity, evidence, anchor, and finding joins must be denied; verify both read and write paths.
8. **Migration ordering/base:** run against a disposable database initialized from a documented snapshot of the live schema plus the known-good migrations before PR #76. A PR #76-only empty database is not evidence of compatibility. Until the Block-2 reconciliation table identifies that base, report this test as blocked rather than passed.

## Release gate

No production migration or deployment until registry tests, proof-bound RPC tests, OTS state propagation, tenant isolation, and full authenticated end-to-end evidence tests pass. A Vercel deployment status alone is not backend or end-to-end proof.
