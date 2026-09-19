-- 095_ai_execution_binding_registry.sql
-- Explicit server-side binding authority for AI run creation.
-- A caller may select a mission/turn and supply idempotency metadata only.
-- Agent/model/provider/tool versions and immutable policy/config references are
-- resolved from this registry before public.ai_start_run is called.

create table if not exists public.ai_execution_bindings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  mission_id text not null,
  mission_version integer not null check (mission_version > 0),
  mission_hash text not null check (mission_hash ~ '^[0-9a-f]{64}$'),

  agent_id uuid not null references public.ai_agents(id) on delete restrict,
  agent_version integer not null check (agent_version > 0),

  model_id text not null,
  model_version integer not null check (model_version > 0),

  provider_id text not null,
  provider_binding_version integer not null check (provider_binding_version > 0),

  tool_id text not null,
  tool_version integer not null check (tool_version > 0),

  policy_version text,
  policy_hash text check (policy_hash is null or policy_hash ~ '^[0-9a-f]{64}$'),
  playbook_version text,
  playbook_hash text check (playbook_hash is null or playbook_hash ~ '^[0-9a-f]{64}$'),
  twin_version text,
  twin_hash text check (twin_hash is null or twin_hash ~ '^[0-9a-f]{64}$'),

  binding_hash text not null check (binding_hash ~ '^[0-9a-f]{64}$'),
  status text not null default 'ACTIVE'
    check (status in ('DRAFT','ACTIVE','RETIRED','REVOKED')),
  created_by uuid,
  created_at timestamptz not null default now(),
  activated_at timestamptz,
  retired_at timestamptz,

  unique (tenant_id, mission_id, mission_version, binding_hash)
);

create unique index if not exists uq_ai_execution_binding_active
  on public.ai_execution_bindings(tenant_id, mission_id, mission_version)
  where status='ACTIVE';

create index if not exists idx_ai_execution_bindings_lookup
  on public.ai_execution_bindings(tenant_id, mission_id, mission_version, status);

alter table public.ai_execution_bindings enable row level security;
revoke all on public.ai_execution_bindings from public,anon,authenticated;

create or replace function public.ai_execution_binding_hash(
  p_tenant_id uuid,
  p_mission_id text,
  p_mission_version integer,
  p_mission_hash text,
  p_agent_id uuid,
  p_agent_version integer,
  p_model_id text,
  p_model_version integer,
  p_provider_id text,
  p_provider_binding_version integer,
  p_tool_id text,
  p_tool_version integer,
  p_policy_hash text default null,
  p_playbook_hash text default null,
  p_twin_hash text default null
) returns text
language sql
immutable
as $$
  select encode(digest(
    convert_to(
      jsonb_build_object(
        'tenant_id',p_tenant_id,
        'mission_id',p_mission_id,
        'mission_version',p_mission_version,
        'mission_hash',p_mission_hash,
        'agent_id',p_agent_id,
        'agent_version',p_agent_version,
        'model_id',p_model_id,
        'model_version',p_model_version,
        'provider_id',p_provider_id,
        'provider_binding_version',p_provider_binding_version,
        'tool_id',p_tool_id,
        'tool_version',p_tool_version,
        'policy_hash',p_policy_hash,
        'playbook_hash',p_playbook_hash,
        'twin_hash',p_twin_hash
      )::text,'UTF8'
    ),'sha256'
  ),'hex')
$$;

create or replace function public.ai_create_execution_binding(
  p_tenant_id uuid,
  p_mission_id text,
  p_mission_version integer,
  p_mission_hash text,
  p_agent_id uuid,
  p_agent_version integer,
  p_model_id text,
  p_model_version integer,
  p_provider_id text,
  p_provider_binding_version integer,
  p_tool_id text,
  p_tool_version integer,
  p_policy_version text default null,
  p_policy_hash text default null,
  p_playbook_version text default null,
  p_playbook_hash text default null,
  p_twin_version text default null,
  p_twin_hash text default null,
  p_created_by uuid default null
) returns public.ai_execution_bindings
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  v public.ai_execution_bindings;
  h text;
begin
  if p_tenant_id is null
     or p_mission_id is null
     or p_mission_version < 1
     or p_mission_hash !~ '^[0-9a-f]{64}$'
     or p_agent_id is null or p_agent_version < 1
     or p_model_id is null or p_model_version < 1
     or p_provider_id is null or p_provider_binding_version < 1
     or p_tool_id is null or p_tool_version < 1 then
    raise exception 'invalid_execution_binding';
  end if;

  if not exists (
    select 1 from public.ai_missions m
     where m.id::text=p_mission_id
       and m.tenant_id=p_tenant_id
       and m.version=p_mission_version
       and m.compiled_hash=p_mission_hash
       and m.status='active'
  ) then
    raise exception 'mission_binding_not_active';
  end if;

  if not exists (
    select 1 from public.ai_agents a
     join public.ai_agent_versions av on av.agent_id=a.id
    where a.id=p_agent_id
      and a.tenant_id=p_tenant_id
      and a.lifecycle_state='ACTIVE'
      and av.version=p_agent_version
      and av.state='ACTIVE'
  ) then
    raise exception 'agent_binding_not_active';
  end if;

  if not exists (
    select 1 from public.ai_models m
     where m.id=p_model_id
       and m.tenant_id=p_tenant_id
       and m.version=p_model_version
       and m.lifecycle_state='ACTIVE'
  ) then
    raise exception 'model_binding_not_active';
  end if;

  if not exists (
    select 1 from public.ai_providers p
     where p.id=p_provider_id
       and (p.tenant_id=p_tenant_id or p.tenant_id is null)
       and p.lifecycle_state='ACTIVE'
       and p.circuit_state <> 'OPEN'
  ) then
    raise exception 'provider_binding_not_active';
  end if;

  if not exists (
    select 1 from public.ai_tools t
     where t.id=p_tool_id
       and (t.tenant_id=p_tenant_id or t.tenant_id is null)
       and t.version=p_tool_version
       and t.lifecycle_state='ACTIVE'
  ) then
    raise exception 'tool_binding_not_active';
  end if;

  h := public.ai_execution_binding_hash(
    p_tenant_id,p_mission_id,p_mission_version,p_mission_hash,
    p_agent_id,p_agent_version,p_model_id,p_model_version,p_provider_id,
    p_provider_binding_version,p_tool_id,p_tool_version,
    p_policy_hash,p_playbook_hash,p_twin_hash
  );

  insert into public.ai_execution_bindings(
    tenant_id,mission_id,mission_version,mission_hash,
    agent_id,agent_version,model_id,model_version,provider_id,
    provider_binding_version,tool_id,tool_version,
    policy_version,policy_hash,playbook_version,playbook_hash,
    twin_version,twin_hash,binding_hash,status,created_by,activated_at
  ) values (
    p_tenant_id,p_mission_id,p_mission_version,p_mission_hash,
    p_agent_id,p_agent_version,p_model_id,p_model_version,p_provider_id,
    p_provider_binding_version,p_tool_id,p_tool_version,
    p_policy_version,p_policy_hash,p_playbook_version,p_playbook_hash,
    p_twin_version,p_twin_hash,h,'ACTIVE',p_created_by,now()
  )
  on conflict (tenant_id,mission_id,mission_version,binding_hash)
  do update set
    status='ACTIVE',
    retired_at=null
  returning * into v;

  return v;
end;
$$;

revoke all on function public.ai_create_execution_binding(
  uuid,text,integer,text,uuid,integer,text,integer,text,integer,text,integer,
  text,text,text,text,text,text,uuid
) from public,anon,authenticated;
grant execute on function public.ai_create_execution_binding(
  uuid,text,integer,text,uuid,integer,text,integer,text,integer,text,integer,
  text,text,text,text,text,text,uuid
) to service_role;

create or replace function workforce.start_ai_turn_run(
  p_user_id uuid,
  p_turn_id uuid,
  p_idempotency_key text,
  p_request_fingerprint text,
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
begin
  if p_user_id is null or p_turn_id is null
     or p_idempotency_key is null or length(trim(p_idempotency_key))=0
     or length(p_idempotency_key)>256
     or p_request_fingerprint is null
     or p_request_fingerprint !~ '^[0-9a-f]{64}$' then
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

  if b.tenant_id <> t.tenant_id
     or b.mission_id <> t.mission_id::text
     or b.mission_version <> t.mission_version
     or b.mission_hash <> t.mission_hash then
    raise exception 'ai_execution_binding_mismatch';
  end if;

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
    p_idempotency_key,
    p_request_fingerprint,
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

revoke all on function workforce.start_ai_turn_run(uuid,uuid,text,text,text,text)
  from public,anon,authenticated;
grant execute on function workforce.start_ai_turn_run(uuid,uuid,text,text,text,text)
  to service_role;

comment on table public.ai_execution_bindings is
'Versioned server-side execution identity binding. Runtime callers cannot choose agent/model/provider/tool identity.';

comment on function workforce.start_ai_turn_run is
'Starts a workforce AI run by resolving exact execution identity from the active server-side binding for the authorized mission.';
