-- Security closure: service-only boundary for RLS-enabled tables without policies
-- and explicit search_path for remaining public helper functions.
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
      and not exists (select 1 from pg_policy p where p.polrelid=c.oid)
  loop
    execute format('revoke all on table %I.%I from anon, authenticated',r.schema_name,r.table_name);
  end loop;
end $$;

do $$
declare r record;
begin
  for r in
    select p.oid,n.nspname,p.proname,pg_get_function_identity_arguments(p.oid) args
    from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.proname in (
        'developer_tenant_id','increment_api_usage','ai_hash_json',
        'ai_execution_config_hash','ai_budget_period_start',
        'ai_security_decision_hash','ai_hash_execution_config',
        'ai_assert_mission_transition','ai_assert_node_transition',
        'ai_assert_tool_transition','ai_execution_binding_hash'
      )
  loop
    execute format(
      'alter function %I.%I(%s) set search_path = public, pg_catalog',
      r.nspname,r.proname,r.args
    );
  end loop;
end $$;
