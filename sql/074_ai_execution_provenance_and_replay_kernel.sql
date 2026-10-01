-- 074_ai_execution_provenance_and_replay_kernel.sql
-- Bind every execution to the exact security decision, resource admission,
-- envelope and immutable execution configuration. Replay is fail-closed.

create table if not exists public.ai_execution_provenance (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  security_decision_id bigint references public.ai_security_decisions(id) on delete restrict,
  execution_config jsonb not null,
  execution_config_hash text not null check (execution_config_hash ~ '^[0-9a-f]{64}$'),
  agent_version integer not null,
  mission_id text not null,
  mission_version integer not null,
  mission_hash text not null check (mission_hash ~ '^[0-9a-f]{64}$'),
  model_id text not null,
  model_version integer not null,
  provider_id text not null,
  provider_binding_version integer not null,
  tool_id text not null,
  tool_version integer not null,
  policy_version text,
  policy_hash text check (policy_hash is null or policy_hash ~ '^[0-9a-f]{64}$'),
  playbook_version text,
  playbook_hash text check (playbook_hash is null or playbook_hash ~ '^[0-9a-f]{64}$'),
  twin_version text,
  twin_hash text check (twin_hash is null or twin_hash ~ '^[0-9a-f]{64}$'),
  envelope_id text,
  envelope_hash text check (envelope_hash is null or envelope_hash ~ '^[0-9a-f]{64}$'),
  admission_hash text check (admission_hash is null or admission_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  unique(run_id),
  unique(run_id,execution_config_hash)
);

create index if not exists idx_ai_execution_provenance_tenant
  on public.ai_execution_provenance(tenant_id,created_at desc);

-- Extend replay ledger so the exact envelope hash is bound to its first claim.
alter table public.ai_execution_replay
  add column if not exists claimed_run_id uuid references public.ai_runs(id) on delete set null;

-- Existing claim function accepted a reused envelope id without checking hash.
-- Replace it with strict identity: same id + different hash is always rejected.
create or replace function public.claim_ai_execution_envelope(
  p_tenant_id uuid,
  p_envelope_id text,
  p_envelope_hash text,
  p_expires_at timestamptz,
  p_run_id uuid default null
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare v_existing public.ai_execution_replay%rowtype;
begin
  if p_tenant_id is null
     or p_envelope_id is null
     or length(p_envelope_id)=0 or length(p_envelope_id)>128
     or p_envelope_hash is null or length(p_envelope_hash)<>64
     or p_envelope_hash !~ '^[0-9a-f]{64}$'
     or p_expires_at <= now() then
    return false;
  end if;

  if p_run_id is not null and not exists (
    select 1 from public.ai_runs
     where id=p_run_id and tenant_id=p_tenant_id
  ) then
    return false;
  end if;

  select * into v_existing
    from public.ai_execution_replay
   where tenant_id=p_tenant_id and envelope_id=p_envelope_id
   for update;

  if found then
    if v_existing.envelope_hash <> p_envelope_hash then
      return false;
    end if;
    return false;
  end if;

  insert into public.ai_execution_replay(
    tenant_id,envelope_id,envelope_hash,expires_at,claimed_run_id
  ) values (
    p_tenant_id,p_envelope_id,p_envelope_hash,p_expires_at,p_run_id
  );

  return true;
end;
$$;

create or replace function public.ai_hash_execution_config(
  p_config jsonb
) returns text
language sql
immutable
strict
as $$
  select encode(digest(convert_to(p_config::text,'UTF8'),'sha256'),'hex')
$$;

-- Atomically attach security decision + exact configuration to a run.
-- The run's tenant and identity are authoritative; callers cannot substitute
-- another tenant/run context.
create or replace function public.ai_bind_execution_provenance(
  p_run_id uuid,
  p_security_decision_id bigint,
  p_execution_config jsonb,
  p_execution_config_hash text,
  p_agent_version integer,
  p_mission_id text,
  p_mission_version integer,
  p_mission_hash text,
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
  p_envelope_id text default null,
  p_envelope_hash text default null,
  p_admission_hash text default null
) returns public.ai_execution_provenance
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  r public.ai_runs;
  d public.ai_security_decisions;
  p public.ai_execution_provenance;
  v_hash text;
begin
  if p_execution_config is null or p_execution_config_hash is null
     or p_execution_config_hash !~ '^[0-9a-f]{64}$'
     or p_mission_hash !~ '^[0-9a-f]{64}$'
     or (p_policy_hash is not null and p_policy_hash !~ '^[0-9a-f]{64}$')
     or (p_playbook_hash is not null and p_playbook_hash !~ '^[0-9a-f]{64}$')
     or (p_twin_hash is not null and p_twin_hash !~ '^[0-9a-f]{64}$')
     or (p_envelope_hash is not null and p_envelope_hash !~ '^[0-9a-f]{64}$')
     then raise exception 'invalid_execution_provenance'; end if;

  select * into r from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  select * into d
    from public.ai_security_decisions
   where id=p_security_decision_id and tenant_id=r.tenant_id and run_id=r.id
   for update;

  if not found or d.decision <> 'ALLOW' then
    raise exception 'execution_security_decision_not_allowed';
  end if;

  if p_agent_version <> r.agent_version
     or p_mission_id <> r.mission_id
     or p_mission_version <> r.mission_version
     or p_mission_hash <> r.mission_hash
     or p_model_id <> r.model_id
     or p_model_version <> r.model_version
     or p_provider_id <> r.provider_id
     or p_provider_binding_version <> r.provider_binding_version then
    raise exception 'execution_identity_mismatch';
  end if;

  v_hash := public.ai_hash_execution_config(p_execution_config);
  if v_hash <> p_execution_config_hash then
    raise exception 'execution_config_hash_mismatch';
  end if;

  insert into public.ai_execution_provenance(
    tenant_id,run_id,security_decision_id,execution_config,execution_config_hash,
    agent_version,mission_id,mission_version,mission_hash,model_id,model_version,
    provider_id,provider_binding_version,tool_id,tool_version,
    policy_version,policy_hash,playbook_version,playbook_hash,twin_version,twin_hash,
    envelope_id,envelope_hash,admission_hash
  ) values (
    r.tenant_id,r.id,d.id,p_execution_config,p_execution_config_hash,
    p_agent_version,p_mission_id,p_mission_version,p_mission_hash,p_model_id,p_model_version,
    p_provider_id,p_provider_binding_version,p_tool_id,p_tool_version,
    p_policy_version,p_policy_hash,p_playbook_version,p_playbook_hash,p_twin_version,p_twin_hash,
    p_envelope_id,p_envelope_hash,p_admission_hash
  )
  on conflict (run_id) do update
    set security_decision_id=excluded.security_decision_id,
        execution_config=excluded.execution_config,
        execution_config_hash=excluded.execution_config_hash,
        agent_version=excluded.agent_version,
        mission_id=excluded.mission_id,
        mission_version=excluded.mission_version,
        mission_hash=excluded.mission_hash,
        model_id=excluded.model_id,
        model_version=excluded.model_version,
        provider_id=excluded.provider_id,
        provider_binding_version=excluded.provider_binding_version,
        tool_id=excluded.tool_id,
        tool_version=excluded.tool_version,
        policy_version=excluded.policy_version,
        policy_hash=excluded.policy_hash,
        playbook_version=excluded.playbook_version,
        playbook_hash=excluded.playbook_hash,
        twin_version=excluded.twin_version,
        twin_hash=excluded.twin_hash,
        envelope_id=excluded.envelope_id,
        envelope_hash=excluded.envelope_hash,
        admission_hash=excluded.admission_hash
  returning * into p;

  update public.ai_runs
     set execution_config_hash=p.execution_config_hash,
         policy_version=p.policy_version,
         policy_hash=p.policy_hash,
         playbook_version=p.playbook_version,
         playbook_hash=p.playbook_hash,
         twin_version=p.twin_version,
         twin_hash=p.twin_hash,
         envelope_version=case when p.envelope_id is not null then coalesce(envelope_version,'1') else envelope_version end,
         envelope_hash=p.envelope_hash
   where id=r.id;

  return p;
end;
$$;

-- Prevent browser/API roles from directly reading or mutating provenance/replay.
alter table public.ai_execution_provenance enable row level security;
alter table public.ai_execution_replay enable row level security;

revoke all on table public.ai_execution_provenance,public.ai_execution_replay
  from anon,authenticated;

comment on table public.ai_execution_provenance is
'Exact per-run execution snapshot. It binds the run to versions/hashes of agent, mission, model, provider binding, tool, policy, playbook, twin, envelope and admission context.';

comment on function public.claim_ai_execution_envelope(uuid,text,text,timestamptz,uuid) is
'Fail-closed replay claim: envelope identity is single-use per tenant and hash mismatches are rejected.';
