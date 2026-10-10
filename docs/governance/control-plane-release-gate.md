# Governance control-plane release gate

## Scope of this change
- Adds the missing `compliance_control_status.evidence_valid_until` column required by `ComplianceService.list_controls`.
- The migration is additive and idempotent.
- No existing evidence is backfilled or marked fresh: NULL remains unknown, not verified.
- This is a staged migration, not a production change. Do not claim the blocker is cleared until the migration is applied and the live query succeeds.

## Mandatory verification before release
1. Confirm the target database/project and migration history.
2. Apply this migration in the approved non-production environment first.
3. Verify the column exists using `information_schema.columns`.
4. Call authenticated `GET /compliance/controls?framework=soc2` and verify no schema error; verify stale/unknown evidence is not shown as passing.
5. Run compliance regression tests and inspect failures before considering a release.
6. Re-query RLS-enabled tables with no policies. For each table, document intended actors and tenant boundary before adding any policy. Do not mass-create permissive policies.
7. Verify audit-event writes, privacy request lifecycle, retention execution, and legal-hold enforcement end-to-end before claiming governance workflows are operational.

## Known release blockers not solved by this migration
- RLS-enabled tables with no policies still require table-by-table access-intent review.
- Empty audit/compliance evidence tables mean governance execution has not yet been demonstrated.
- PIA/DSAR, retention and legal-hold workflows remain unverified end-to-end.
- No CI, production migration, secret change, or deployment is authorized by this branch commit.

## RLS inventory query
```sql
SELECT n.nspname AS schema_name, c.relname AS table_name
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname = 'public'
  AND c.relrowsecurity
  AND NOT EXISTS (
    SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid
  )
ORDER BY c.relname;
```
