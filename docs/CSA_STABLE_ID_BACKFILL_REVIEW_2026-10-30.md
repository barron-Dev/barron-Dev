# CSA stable-ID backfill — review candidate only

Date: 2026-10-30  
Project: `whcomikcftbousoqzeal`

## Status

**Prepared for review; not an applied migration.** This is intentionally documented outside the migration directory. Do not execute directly in production. The live ledger identifies migration `20260916022425 / compliance_control_library` as the origin of the `stable_id` column and partial unique index. A current read-only query confirmed exactly the two expected HIPAA rows remain NULL:

| Control | Live row ID | Proposed stable ID |
|---|---|---|
| HIPAA 164.308(a)(1) | `f9bc9f32-34d2-4553-80cd-fd66d3414f5a` | `hipaa.164.308.a.1` |
| HIPAA 164.312(b) | `3025c96a-e0f9-4e1b-ac6e-adb1b84b7ced` | `hipaa.164.312.b` |

No matching proposed stable IDs were found on other rows in that read. The primary key and all four referencing foreign-key relationships remain unchanged by this update.

## Candidate forward-only SQL

The candidate is fail-closed: it asserts exactly two NULL targets, asserts no existing stable-ID collision, updates only those two framework/code pairs, and verifies no NULL stable IDs remain. The existing partial unique index remains the uniqueness enforcement mechanism.

```sql
do $migration$
declare
  v_target_count integer;
  v_null_count integer;
  v_conflict_count integer;
  v_updated_count integer;
begin
  select count(*)
    into v_target_count
    from public.compliance_controls
   where framework = 'hipaa'
     and control_code in ('164.308(a)(1)', '164.312(b)')
     and stable_id is null;

  if v_target_count <> 2 then
    raise exception 'CSA stable-id backfill expected exactly 2 NULL HIPAA targets; found %', v_target_count;
  end if;

  select count(*)
    into v_null_count
    from public.compliance_controls
   where stable_id is null;

  if v_null_count <> 2 then
    raise exception 'CSA stable-id backfill expected exactly 2 NULL stable_id values globally; found %', v_null_count;
  end if;

  select count(*)
    into v_conflict_count
    from public.compliance_controls
   where stable_id in ('hipaa.164.308.a.1', 'hipaa.164.312.b')
     and not (
       framework = 'hipaa'
       and control_code in ('164.308(a)(1)', '164.312(b)')
     );

  if v_conflict_count <> 0 then
    raise exception 'CSA stable-id backfill found % conflicting stable_id rows', v_conflict_count;
  end if;

  update public.compliance_controls
     set stable_id = case control_code
       when '164.308(a)(1)' then 'hipaa.164.308.a.1'
       when '164.312(b)' then 'hipaa.164.312.b'
     end
   where framework = 'hipaa'
     and control_code in ('164.308(a)(1)', '164.312(b)')
     and stable_id is null;

  get diagnostics v_updated_count = row_count;
  if v_updated_count <> 2 then
    raise exception 'CSA stable-id backfill expected to update 2 rows; updated %', v_updated_count;
  end if;

  select count(*)
    into v_null_count
    from public.compliance_controls
   where stable_id is null;

  if v_null_count <> 0 then
    raise exception 'CSA stable-id backfill left % NULL stable_id values', v_null_count;
  end if;
end;
$migration$;
```

## Preconditions before migration creation/application

1. Re-run the exact target and conflict queries against the intended environment immediately before applying.
2. Confirm the partial unique index `compliance_controls_stable_id_uidx` is valid and ready.
3. Confirm the two target UUIDs still map to the same HIPAA framework/control codes.
4. Generate the real migration using the repository's pinned Supabase CLI workflow; do not hand-invent a migration version or insert a ledger row manually.
5. Run local migration validation and tests; review Supabase security advisors.
6. Obtain explicit production migration approval before applying.
7. After application, verify both IDs, zero NULL stable IDs, no duplicate non-NULL IDs, and unchanged target UUIDs/FK references.

## Safety boundary

This SQL only backfills two stable identifiers. It does not create/recreate controls, alter primary keys, rewrite foreign keys, or change tenant data. It is not a substitute for resolving the separate untracked freshness-column provenance documented in `CSA_MIGRATION_RECONCILIATION_2026-10-30.md`.
