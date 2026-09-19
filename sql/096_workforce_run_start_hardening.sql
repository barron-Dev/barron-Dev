-- 096_workforce_run_start_hardening.sql
-- Workforce run start must derive the request fingerprint and final
-- idempotency identity server-side. The caller may supply only an opaque
-- idempotency token; it cannot influence execution identity or fingerprint.

create or replace function workforce.start_ai_turn_run(
  p_user_id uuid,
  p_turn_id uuid,
  p_idempotency_token text,
  p_trace_id text default null,
  p_correlation_id text default null
) returns public.ai_runs
language plpgsql
security definer
set search_path = workforce,public,pg_catalog
as $$
declare
  e workforce.employees%rowtype;
  t workforce.ai_turns%rowtype;
  b public.ai_execution_bindings%rowtype;
  r public.ai_runs;
  v_key text;
  v_fingerprint text;
begin
  if p_user_id is null or p_turn_id is null
     or p_idempotency_token is null
     or length(trim(p_idempotency_token))=0
     or length(p_idempotency_token)>128 then
    raise exception 'invalid_workforce_run_start';
  end if;

  select * into e
    from workforce.employees
   where user_id=p_user_id
   for update;

  if not found or e.status <> 'active' then
    raise exception 'workforce_employee_not_active';
  end if;

  select * into t
    from workforce.ai_turns
   where id=p_turn_id
   for update;

  if not found or t.employee_id <> e.id then
    raise exception 'workforce_ai_turn_owner_mismatch';
  end if;

  if t.status <> 'accepted' then
    raise exception 'ai_turn_not_startable';
  end if;

  if t.ai_run_id is not null then
    select * into r from public.ai_runs where id=t.ai_run_id for update;
    if not found then
      raise exception 'ai_turn_run_binding_missing';
    end if;
    return r;
  end if;

  select * into b
    from public.ai_execution_bindings
   where tenant_id=t.tenant_id
     and mission_id=t.mission_id::text
     and mission_version=t.mission_version
     and mission_hash=t.mission_hash
     and status='ACTIVE'
   limit 1
   for update;

  if not found then
    raise exception 'ai_execution_binding_not_available';
  end if;

  v_key := left(
    'workforce-turn:' || t.id::text || ':' || trim(p_idempotency_token),
    256
  );

  v_fingerprint := encode(
    digest(
      convert_to(
        jsonb_build_object(
          'turn_id',t.id,
          'session_id',t.session_id,
          'tenant_id',t.tenant_id,
          'input_hash',t.input_hash,
          'mission_id',b.mission_id,
          'mission_version',b.mission_version,
          'mission_hash',b.mission_hash,
          'binding_hash',b.binding_hash
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  );

  r := public.ai_start_run(
    t.tenant_id,
    b.agent_id,
    b.agent_version,
    b.mission_id,
    b.mission_version,
    b.mission_hash,
    b.model_id,
    b.model_version,
    b.provider_id,
    b.provider_binding_version,
    v_key,
    v_fingerprint,
    p_trace_id,
    p_correlation_id
  );

  if t.ai_run_id is null then
    update workforce.ai_turns
       set ai_run_id=r.id
     where id=t.id;
  elsif t.ai_run_id <> r.id then
    raise exception 'ai_turn_already_bound_to_different_run';
  end if;

  return r;
end;
$$;

revoke all on function workforce.start_ai_turn_run(uuid,uuid,text,text,text)
  from public,anon,authenticated;
grant execute on function workforce.start_ai_turn_run(uuid,uuid,text,text,text)
  to service_role;

comment on function workforce.start_ai_turn_run(uuid,uuid,text,text,text) is
'Workforce run creation derives request fingerprint and exact execution identity server-side from the accepted turn and active execution binding.';
