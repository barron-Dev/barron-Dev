begin;
do $$
declare r record;
begin
 for r in select tablename from pg_tables where schemaname='public' and tablename like 'mdi_%'
 loop
   execute format('drop policy if exists %I on public.%I', 'mdi_service_role_all', r.tablename);
   execute format('create policy %I on public.%I for all to service_role using (true) with check (true)', 'mdi_service_role_all', r.tablename);
 end loop;
end $$;
commit;