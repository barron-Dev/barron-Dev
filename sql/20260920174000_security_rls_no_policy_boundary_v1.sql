-- RLS is intentionally enabled on these internal tables without client policies.
-- Keep the client boundary closed: authenticated/anon must not access them directly.
do $$
declare r record;
begin
  for r in
    select n.nspname schema_name, c.relname table_name
    from pg_class c
    join pg_namespace n on n.oid=c.relnamespace
    left join pg_policies p on p.schemaname=n.nspname and p.tablename=c.relname
    where c.relkind='r'
      and c.relrowsecurity
      and n.nspname in ('public','workforce')
      and p.tablename is null
  loop
    execute format('revoke all on table %I.%I from anon, authenticated', r.schema_name, r.table_name);
  end loop;
end $$;
