-- 071_ai_foundation_kernel.sql
-- Cyclothone AI foundation: immutable registry + durable execution kernel.
-- This migration is source-controlled only; production application is intentionally separate.
-- Security invariant: clients never write these tables directly; privileged RPCs are service_role-only.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Agent registry compatibility: preserve existing ai_agents.status contract.
-- ---------------------------------------------------------------------------

alter table public.ai_agents
  add column if not exists lifecycle_state text,
  add column if not exists current_version integer,
  add column if not exists health_state text not null default 'UNKNOWN',
  add column if not exists last_heartbeat_at timestamptz,
  add column if not exists administrator_id uuid,
  add column if not exists capabilities jsonb not null default '{}'::jsonb;

update public.ai_agents
   set lifecycle_state = case lower(status)
       when 'active' then 'ACTIVE'
       when 'suspended' then 'SUSPENDED'
       when 'revoked' then 'REVOKED'
       when 'deprecated' then 'DEPRECATED'
       else 'REGISTERED'
   end
 where lifecycle_state is null;

alter table public.ai_agents
  alter column lifecycle_state set default 'REGISTERED';

alter table public.ai_agents
  drop constraint if exists ai_agents_lifecycle_state_check;

alter table public.ai_agents
  add constraint ai_agents_lifecycle_state_check
  check (lifecycle_state in ('REGISTERED','VALIDATING','ACTIVE','SUSPENDED','DEPRECATED','REVOKED'));

alter table public.ai_agents
  drop constraint if exists ai_agents_health_state_check;

alter table public.ai_agents
  add constraint ai_agents_health_state_check
  check (health_state in ('UNKNOWN','HEALTHY','DEGRADED','DOWN'));

create table if not exists public.ai_agent_versions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  agent_id uuid not null references public.ai_agents(id) on delete cascade,
  version integer not null check (version > 0),
  config jsonb not null,
  config_hash text not null check (config_hash ~ '^[0-9a-f]{64}$'),
  state text not null default 'DRAFT'
    check (state in ('DRAFT','VALIDATING','ACTIVE','DEPRECATED','REVOKED')),
  created_by uuid,
  created_at timestamptz not null default now(),
  activated_at timestamptz,
  deprecated_at timestamptz,
  revoked_at timestamptz,
  unique (agent_id, version),
  unique (agent_id, version, config_hash)
);

create index if not exists idx_ai_agent_versions_active
  on public.ai_agent_versions(tenant_id, agent_id, version desc)
  where state='ACTIVE';

-- Keep the legacy agent status and the new lifecycle state coherent.
create or replace function public.sync_ai_agent_lifecycle()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if tg_op = 'INSERT' then
    if new.lifecycle_state is null then
      new.lifecycle_state := case lower(coalesce(new.status,'registered'))
        when 'active' then 'ACTIVE'
        when 'suspended' then 'SUSPENDED'
        when 'revoked' then 'REVOKED'
        when 'deprecated' then 'DEPRECATED'
        else 'REGISTERED'
      end;
    end if;
    new.status := lower(new.lifecycle_state);
    return new;
  end if;

  if new.lifecycle_state is distinct from old.lifecycle_state then
    new.status := lower(new.lifecycle_state);
  elsif new.status is distinct from old.status then
    new.lifecycle_state := case lower(new.status)
      when 'active' then 'ACTIVE'
      when 'suspended' then 'SUSPENDED'
      when 'revoked' then 'REVOKED'
      when 'deprecated' then 'DEPRECATED'
      else 'REGISTERED'
    end;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_sync_ai_agent_lifecycle on public.ai_agents;
create trigger trg_sync_ai_agent_lifecycle
before insert or update of status, lifecycle_state
on public.ai_agents
for each row execute function public.sync_ai_agent_lifecycle();

-- ---------------------------------------------------------------------------
-- Model/provider/tool registries use text IDs to match the existing binding
-- authority (067-070) instead of inventing a parallel UUID identity domain.
-- ---------------------------------------------------------------------------

create table if not exists public.ai_models (
  id text primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  provider_model_key text not null,
  display_name text not null,
  version integer not null default 1 check (version > 0),
  lifecycle_state text not null default 'REGISTERED'
    check (lifecycle_state in ('REGISTERED','VALIDATING','ACTIVE','DEPRECATED','RETIRED','REVOKED')),
  modality text not null default 'text',
  context_limit integer check (context_limit is null or context_limit > 0),
  cost_meta jsonb not null default '{}'::jsonb,
  residency jsonb not null default '{}'::jsonb,
  latency_target_ms integer check (latency_target_ms is null or latency_target_ms > 0),
  rate_limit jsonb not null default '{}'::jsonb,
  concurrency_limit integer check (concurrency_limit is null or concurrency_limit > 0),
  model_hash text check (model_hash is null or model_hash ~ '^[0-9a-f]{64}$'),
  artifact_hash text check (artifact_hash is null or artifact_hash ~ '^[0-9a-f]{64}$'),
  safety_eval jsonb not null default '{}'::jsonb,
  benchmark jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  activated_at timestamptz,
  deprecated_at timestamptz,
  retired_at timestamptz,
  unique (tenant_id, provider_model_key, version)
);

create index if not exists idx_ai_models_active
  on public.ai_models(tenant_id, provider_model_key, version desc)
  where lifecycle_state='ACTIVE';

create table if not exists public.ai_providers (
  id text primary key,
  tenant_id uuid references public.tenants(id) on delete cascade,
  provider_key text not null,
  display_name text not null,
  lifecycle_state text not null default 'REGISTERED'
    check (lifecycle_state in ('REGISTERED','VALIDATING','ACTIVE','ROTATING','REVOKED')),
  health_state text not null default 'UNKNOWN'
    check (health_state in ('UNKNOWN','HEALTHY','DEGRADED','DOWN')),
  circuit_state text not null default 'CLOSED'
    check (circuit_state in ('CLOSED','OPEN','HALF_OPEN')),
  circuit_opened_at timestamptz,
  circuit_probe_lease uuid,
  circuit_probe_expires timestamptz,
  latency_ms integer,
  availability numeric(5,4) check (availability is null or availability between 0 and 1),
  quota jsonb not null default '{}'::jsonb,
  cost_meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (tenant_id, provider_key)
);

create table if not exists public.ai_tools (
  id text primary key,
  tenant_id uuid references public.tenants(id) on delete cascade,
  tool_key text not null,
  version integer not null default 1 check (version > 0),
  schema jsonb not null default '{}'::jsonb,
  schema_hash text not null check (schema_hash ~ '^[0-9a-f]{64}$'),
  risk_level text not null default 'LOW'
    check (risk_level in ('LOW','MEDIUM','HIGH','CRITICAL')),
  lifecycle_state text not null default 'REGISTERED'
    check (lifecycle_state in ('REGISTERED','ACTIVE','DEPRECATED','REVOKED')),
  health_state text not null default 'UNKNOWN'
    check (health_state in ('UNKNOWN','HEALTHY','DEGRADED','DOWN')),
  created_at timestamptz not null default now(),
  unique (tenant_id, tool_key, version)
);

create index if not exists idx_ai_tools_active
  on public.ai_tools(tenant_id, tool_key, version desc)
  where lifecycle_state='ACTIVE';

create or replace function public.ai_hash_json(p jsonb)
returns text
language sql
immutable
strict
as $$
  select encode(digest(
    convert_to(p::text, 'UTF8'),
    'sha256'
  ), 'hex')
$$;

-- ---------------------------------------------------------------------------
-- Durable run kernel.
-- ---------------------------------------------------------------------------

create table if not exists public.ai_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,

  agent_id uuid not null references public.ai_agents(id) on delete restrict,
  agent_version integer not null,

  mission_id text not null,
  mission_version integer not null,
  mission_hash text not null check (mission_hash ~ '^[0-9a-f]{64}$'),

  model_id text not null,
  model_version integer not null,

  provider_id text not null,
  provider_binding_version integer not null default 1,

  run_state text not null default 'REQUESTED'
    check (run_state in (
      'REQUESTED','QUEUED','RUNNING','STREAMING','WAITING_APPROVAL',
      'COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED',
      'RECOVERING','STUCK'
    )),

  request_fingerprint text not null check (request_fingerprint ~ '^[0-9a-f]{64}$'),
  idempotency_key text not null,
  trace_id text,
  correlation_id text,

  tokens_in bigint not null default 0 check (tokens_in >= 0),
  tokens_out bigint not null default 0 check (tokens_out >= 0),
  tokens_cached bigint not null default 0 check (tokens_cached >= 0),

  latency_ms bigint check (latency_ms is null or latency_ms >= 0),
  queue_ms bigint check (queue_ms is null or queue_ms >= 0),
  exec_ms bigint check (exec_ms is null or exec_ms >= 0),
  cost_usd numeric(18,8) not null default 0 check (cost_usd >= 0),

  policy_version text,
  policy_hash text check (policy_hash is null or policy_hash ~ '^[0-9a-f]{64}$'),
  playbook_version text,
  playbook_hash text check (playbook_hash is null or playbook_hash ~ '^[0-9a-f]{64}$'),
  twin_version text,
  twin_hash text check (twin_hash is null or twin_hash ~ '^[0-9a-f]{64}$'),
  envelope_version text,
  envelope_hash text check (envelope_hash is null or envelope_hash ~ '^[0-9a-f]{64}$'),
  execution_config_hash text check (
    execution_config_hash is null or execution_config_hash ~ '^[0-9a-f]{64}$'
  ),

  error jsonb,
  heartbeat_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),

  unique (tenant_id, idempotency_key)
);

create index if not exists idx_ai_runs_state
  on public.ai_runs(tenant_id, run_state, created_at desc);

create index if not exists idx_ai_runs_worker
  on public.ai_runs(run_state, heartbeat_at, created_at);

create table if not exists public.ai_run_transitions (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  from_state text,
  to_state text not null,
  reason text,
  actor text not null default 'system',
  transition_key text not null,
  at timestamptz not null default now(),
  unique (run_id, transition_key)
);

create index if not exists idx_ai_run_transitions_run
  on public.ai_run_transitions(run_id, at);

-- Immutable transition graph. No direct run-state UPDATE is accepted through
-- the privileged transition function unless this graph permits it.
create or replace function public.ai_assert_transition(
  p_from text,
  p_to text
) returns boolean
language sql
immutable
strict
as $$
  select case p_from
    when 'REQUESTED' then p_to in ('QUEUED','REJECTED','CANCELLED')
    when 'QUEUED' then p_to in ('RUNNING','CANCELLED','TIMEOUT','REJECTED')
    when 'RUNNING' then p_to in ('STREAMING','WAITING_APPROVAL','COMPLETED','FAILED','TIMEOUT','CANCELLED','STUCK')
    when 'STREAMING' then p_to in ('RUNNING','COMPLETED','FAILED','TIMEOUT','CANCELLED','STUCK')
    when 'WAITING_APPROVAL' then p_to in ('RUNNING','REJECTED','CANCELLED','TIMEOUT','STUCK')
    when 'STUCK' then p_to in ('RECOVERING','FAILED','CANCELLED')
    when 'RECOVERING' then p_to in ('QUEUED','RUNNING','FAILED','CANCELLED')
    else false
  end
$$;

-- Privileged transition function. Service-role only; tenant is derived from the
-- locked run row rather than trusted from the caller.
create or replace function public.ai_transition_run(
  p_run_id uuid,
  p_to text,
  p_reason text default null,
  p_actor text default 'system'
) returns public.ai_runs
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.ai_runs;
  v_from text;
  v_key text;
begin
  if p_run_id is null or p_to is null then
    raise exception 'invalid_transition_request';
  end if;

  select *
    into r
    from public.ai_runs
   where id = p_run_id
   for update;

  if not found then
    raise exception 'run_not_found';
  end if;

  v_from := r.run_state;

  if v_from = p_to then
    return r;
  end if;

  if not public.ai_assert_transition(v_from, p_to) then
    raise exception 'invalid_transition % -> %', v_from, p_to;
  end if;

  v_key := v_from || '>' || p_to || ':' ||
           coalesce(p_reason,'') || ':' || clock_timestamp()::text;

  update public.ai_runs
     set run_state = p_to,
         started_at = case
           when p_to in ('RUNNING','STREAMING') and started_at is null then now()
           else started_at
         end,
         finished_at = case
           when p_to in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED') then now()
           else finished_at
         end,
         heartbeat_at = case
           when p_to in ('RUNNING','STREAMING','RECOVERING') then now()
           else heartbeat_at
         end
   where id = p_run_id
   returning * into r;

  insert into public.ai_run_transitions(
    tenant_id, run_id, from_state, to_state, reason, actor, transition_key
  )
  values (
    r.tenant_id, r.id, v_from, p_to, p_reason,
    left(coalesce(p_actor,'system'),128), v_key
  );

  return r;
end;
$$;

-- Start is genuinely idempotent: same key + same fingerprint returns the
-- existing run; same key + different fingerprint is a hard conflict.
create or replace function public.ai_start_run(
  p_tenant_id uuid,
  p_agent_id uuid,
  p_agent_version integer,
  p_mission_id text,
  p_mission_version integer,
  p_mission_hash text,
  p_model_id text,
  p_model_version integer,
  p_provider_id text,
  p_provider_binding_version integer,
  p_idempotency_key text,
  p_request_fingerprint text,
  p_trace_id text default null,
  p_correlation_id text default null
) returns public.ai_runs
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.ai_runs;
begin
  if p_tenant_id is null or p_agent_id is null or p_mission_id is null
     or p_model_id is null or p_provider_id is null
     or p_idempotency_key is null or length(p_idempotency_key) > 256
     or p_request_fingerprint is null
     or p_request_fingerprint !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_run_identity';
  end if;

  insert into public.ai_runs(
    tenant_id, agent_id, agent_version,
    mission_id, mission_version, mission_hash,
    model_id, model_version, provider_id, provider_binding_version,
    idempotency_key, request_fingerprint, trace_id, correlation_id
  )
  values (
    p_tenant_id, p_agent_id, p_agent_version,
    p_mission_id, p_mission_version, p_mission_hash,
    p_model_id, p_model_version, p_provider_id, p_provider_binding_version,
    p_idempotency_key, p_request_fingerprint, p_trace_id, p_correlation_id
  )
  on conflict (tenant_id, idempotency_key) do nothing
  returning * into r;

  if r.id is null then
    select *
      into r
      from public.ai_runs
     where tenant_id = p_tenant_id
       and idempotency_key = p_idempotency_key
     for update;

    if r.request_fingerprint <> p_request_fingerprint then
      raise exception 'idempotency_conflict';
    end if;
  end if;

  return r;
end;
$$;

-- Exact execution snapshot hash. This is the binding checksum stored with the run.
create or replace function public.ai_execution_config_hash(
  p_agent_id uuid,
  p_agent_version integer,
  p_mission_id text,
  p_mission_version integer,
  p_mission_hash text,
  p_model_id text,
  p_model_version integer,
  p_provider_id text,
  p_provider_binding_version integer,
  p_policy_hash text default null,
  p_playbook_hash text default null,
  p_twin_hash text default null,
  p_envelope_hash text default null
) returns text
language sql
immutable
as $$
  select encode(digest(
    convert_to(
      jsonb_build_object(
        'agent_id', p_agent_id,
        'agent_version', p_agent_version,
        'mission_id', p_mission_id,
        'mission_version', p_mission_version,
        'mission_hash', p_mission_hash,
        'model_id', p_model_id,
        'model_version', p_model_version,
        'provider_id', p_provider_id,
        'provider_binding_version', p_provider_binding_version,
        'policy_hash', p_policy_hash,
        'playbook_hash', p_playbook_hash,
        'twin_hash', p_twin_hash,
        'envelope_hash', p_envelope_hash
      )::text,
      'UTF8'
    ),
    'sha256'
  ), 'hex')
$$;

-- ---------------------------------------------------------------------------
-- Mission/node/tool durable execution records.
-- ---------------------------------------------------------------------------

create table if not exists public.ai_mission_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  mission_id text not null,
  mission_version integer not null,
  mission_hash text not null check (mission_hash ~ '^[0-9a-f]{64}$'),
  state text not null default 'QUEUED'
    check (state in ('QUEUED','RUNNING','WAITING_APPROVAL','COMPLETED','FAILED','CANCELLED','STUCK')),
  node_count integer not null default 0,
  completed_nodes integer not null default 0,
  failed_node text,
  branch_trace jsonb not null default '[]'::jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  unique (run_id)
);

create table if not exists public.ai_node_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  mission_run_id uuid not null references public.ai_mission_runs(id) on delete cascade,
  node_id text not null,
  attempt integer not null default 1 check (attempt > 0),
  state text not null default 'QUEUED'
    check (state in ('QUEUED','RUNNING','COMPLETED','FAILED','SKIPPED','TIMEOUT','CANCELLED')),
  input_hash text check (input_hash is null or input_hash ~ '^[0-9a-f]{64}$'),
  output_hash text check (output_hash is null or output_hash ~ '^[0-9a-f]{64}$'),
  latency_ms bigint check (latency_ms is null or latency_ms >= 0),
  retry_count integer not null default 0 check (retry_count >= 0),
  max_retries integer not null default 3 check (max_retries between 0 and 32),
  backoff_ms integer not null default 500 check (backoff_ms between 0 and 3600000),
  next_retry_at timestamptz,
  error jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  unique (mission_run_id, node_id, attempt)
);

create table if not exists public.ai_tool_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  node_run_id uuid references public.ai_node_runs(id) on delete set null,
  tool_id text not null,
  tool_version integer not null,
  args_hash text check (args_hash is null or args_hash ~ '^[0-9a-f]{64}$'),
  result_hash text check (result_hash is null or result_hash ~ '^[0-9a-f]{64}$'),
  state text not null default 'QUEUED'
    check (state in ('QUEUED','RUNNING','COMPLETED','FAILED','BLOCKED','APPROVAL_REQUIRED','TIMEOUT','CANCELLED')),
  latency_ms bigint,
  cost_usd numeric(18,8) not null default 0,
  error jsonb,
  created_at timestamptz not null default now(),
  finished_at timestamptz
);

create index if not exists idx_ai_tool_runs_run on public.ai_tool_runs(tenant_id, run_id, created_at);

-- ---------------------------------------------------------------------------
-- RLS: authenticated tenant members may read their own registry/run data.
-- All mutations remain service_role-only through the privileged API.
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array[
    'ai_agent_versions','ai_models','ai_providers','ai_tools',
    'ai_runs','ai_run_transitions','ai_mission_runs','ai_node_runs','ai_tool_runs'
  ]
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from anon', t);
    execute format('revoke all on table public.%I from authenticated', t);
  end loop;
end $$;

-- Read access is intentionally membership-based; no user_metadata authorization.
drop policy if exists ai_agent_versions_member_read on public.ai_agent_versions;
create policy ai_agent_versions_member_read on public.ai_agent_versions
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_agent_versions.tenant_id
     and tm.user_id = auth.uid()
));

drop policy if exists ai_models_member_read on public.ai_models;
create policy ai_models_member_read on public.ai_models
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_models.tenant_id
     and tm.user_id = auth.uid()
));

drop policy if exists ai_providers_member_read on public.ai_providers;
create policy ai_providers_member_read on public.ai_providers
for select to authenticated
using (
  tenant_id is null
  or exists (
    select 1 from public.tenant_members tm
     where tm.tenant_id = ai_providers.tenant_id
       and tm.user_id = auth.uid()
  )
);

drop policy if exists ai_tools_member_read on public.ai_tools;
create policy ai_tools_member_read on public.ai_tools
for select to authenticated
using (
  tenant_id is null
  or exists (
    select 1 from public.tenant_members tm
     where tm.tenant_id = ai_tools.tenant_id
       and tm.user_id = auth.uid()
  )
);

drop policy if exists ai_runs_member_read on public.ai_runs;
create policy ai_runs_member_read on public.ai_runs
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_runs.tenant_id
     and tm.user_id = auth.uid()
));

drop policy if exists ai_run_transitions_member_read on public.ai_run_transitions;
create policy ai_run_transitions_member_read on public.ai_run_transitions
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_run_transitions.tenant_id
     and tm.user_id = auth.uid()
));

drop policy if exists ai_mission_runs_member_read on public.ai_mission_runs;
create policy ai_mission_runs_member_read on public.ai_mission_runs
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_mission_runs.tenant_id
     and tm.user_id = auth.uid()
));

drop policy if exists ai_node_runs_member_read on public.ai_node_runs;
create policy ai_node_runs_member_read on public.ai_node_runs
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_node_runs.tenant_id
     and tm.user_id = auth.uid()
));

drop policy if exists ai_tool_runs_member_read on public.ai_tool_runs;
create policy ai_tool_runs_member_read on public.ai_tool_runs
for select to authenticated
using (exists (
  select 1 from public.tenant_members tm
   where tm.tenant_id = ai_tool_runs.tenant_id
     and tm.user_id = auth.uid()
));

-- Existing public tables have their own policies. The new privileged RPCs are
-- deliberately inaccessible to browser roles.
revoke all on function public.ai_assert_transition(text,text)
  from public, anon, authenticated;
revoke all on function public.ai_transition_run(uuid,text,text,text)
  from public, anon, authenticated;
revoke all on function public.ai_start_run(uuid,uuid,integer,text,integer,text,text,integer,text,integer,text,text,text,text)
  from public, anon, authenticated;
revoke all on function public.ai_execution_config_hash(uuid,integer,text,integer,text,text,integer,text,integer,text,text,text,text)
  from public, anon, authenticated;

grant execute on function public.ai_assert_transition(text,text) to service_role;
grant execute on function public.ai_transition_run(uuid,text,text,text) to service_role;
grant execute on function public.ai_start_run(uuid,uuid,integer,text,integer,text,text,integer,text,integer,text,text,text,text) to service_role;
grant execute on function public.ai_execution_config_hash(uuid,integer,text,integer,text,text,integer,text,integer,text,text,text,text) to service_role;

-- No browser role gets table mutation privileges.
grant select on public.ai_agent_versions, public.ai_models, public.ai_providers,
  public.ai_tools, public.ai_runs, public.ai_run_transitions,
  public.ai_mission_runs, public.ai_node_runs, public.ai_tool_runs
to authenticated;

-- Foundation invariants:
-- 1) every run has one immutable tenant/idempotency identity;
-- 2) transitions are serialized by row lock;
-- 3) from_state is captured BEFORE mutation;
-- 4) privileged mutation RPCs derive tenant from stored rows where possible;
-- 5) execution configuration can be hashed into one reproducible binding;
-- 6) mission/node/tool execution is durable, not worker-memory state.
