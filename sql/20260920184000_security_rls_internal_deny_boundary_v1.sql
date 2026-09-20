-- Close the remaining RLS-without-policy boundary.
-- These tables are internal service/workforce state. Client roles receive an explicit
-- deny policy (false) rather than relying only on revoked table privileges.
-- service_role/backend SECURITY DEFINER paths are not constrained by these client policies.

do $$
declare r record;
begin
  for r in
    select n.nspname schema_name,c.relname table_name
    from pg_class c
    join pg_namespace n on n.oid=c.relnamespace
    where c.relkind='r'
      and c.relrowsecurity
      and n.nspname in ('public','workforce')
      and not exists (
        select 1 from pg_policies p
        where p.schemaname=n.nspname and p.tablename=c.relname
      )
  loop
    execute format(
      'create policy %I on %I.%I for all to anon, authenticated using (false) with check (false)',
      'deny_client_' || r.table_name,
      r.schema_name,
      r.table_name
    );
  end loop;
end $$;
