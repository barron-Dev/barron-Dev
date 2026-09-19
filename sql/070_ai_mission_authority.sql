-- Protected resolver for the exact tenant-scoped Mission version/hash used for AI execution.
create or replace function public.resolve_ai_mission_binding(
    p_tenant_id uuid,
    p_mission_id text,
    p_version integer,
    p_compiled_hash text
) returns table (
    mission_id text,
    version integer,
    compiled_hash text,
    status text,
    is_dag boolean
)
language sql
security definer
set search_path = public
as $$
    select m.id::text, m.version, m.compiled_hash, m.status, m.is_dag
      from public.ai_missions m
     where m.tenant_id = p_tenant_id
       and m.id::text = p_mission_id
       and m.version = p_version
       and m.compiled_hash = p_compiled_hash
       and m.status = 'active'
       and m.is_dag = true
     limit 1
$$;

revoke all on function public.resolve_ai_mission_binding(uuid,text,integer,text)
    from public, anon, authenticated;
grant execute on function public.resolve_ai_mission_binding(uuid,text,integer,text)
    to service_role;
