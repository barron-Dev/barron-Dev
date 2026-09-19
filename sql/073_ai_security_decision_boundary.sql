-- 073_ai_security_decision_boundary.sql
-- Canonical security decision boundary for AI execution.
-- This block owns kill-switch state, security decisions, and destructive-action
-- approval gates. It does not replace Mission Authority, Envelope Authority,
-- Replay Protection, Digital Twin, or the existing Execution Gate.

create table if not exists public.ai_kill_switches (
  id uuid primary key default gen_random_uuid(),
  scope text not null check (scope in ('GLOBAL','TENANT','AGENT','MISSION','PROVIDER','TOOL')),
  scope_id text,
  engaged boolean not null default false,
  reason text,
  engaged_by text,
  engaged_at timestamptz,
  released_by text,
  released_at timestamptz,
  version bigint not null default 1,
  metadata jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  check (
    (scope='GLOBAL' and scope_id is null)
    or (scope<>'GLOBAL' and scope_id is not null)
  ),
  unique (scope,scope_id)
);

create index if not exists idx_ai_kill_switch_lookup
  on public.ai_kill_switches(scope,scope_id,engaged);

create table if not exists public.ai_security_decisions (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid references public.ai_runs(id) on delete set null,
  decision text not null check (decision in ('ALLOW','DENY','APPROVAL_REQUIRED')),
  reason_code text not null,
  risk_level text not null check (risk_level in ('LOW','MEDIUM','HIGH','CRITICAL')),
  destructive boolean not null default false,
  approval_required boolean not null default false,
  approval_ref text,
  policy_version text,
  policy_hash text check (policy_hash is null or policy_hash ~ '^[0-9a-f]{64}$'),
  kill_switch_version bigint,
  actor text not null default 'system',
  correlation_id text,
  decision_hash text not null check (decision_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now()
);

create index if not exists idx_ai_security_decisions_run
  on public.ai_security_decisions(tenant_id,run_id,created_at desc);

create unique index if not exists uq_ai_security_decision_hash
  on public.ai_security_decisions(decision_hash);

-- Hash includes the decision facts, making the record tamper-evident even
-- though the table remains append-only to application roles.
create or replace function public.ai_security_decision_hash(
  p_tenant_id uuid,
  p_run_id uuid,
  p_decision text,
  p_reason_code text,
  p_risk_level text,
  p_destructive boolean,
  p_approval_required boolean,
  p_approval_ref text,
  p_policy_version text,
  p_policy_hash text,
  p_kill_switch_version bigint,
  p_actor text,
  p_correlation_id text
) returns text
language sql
immutable
strict
as $$
  select encode(digest(
    convert_to(
      jsonb_build_object(
        'tenant_id',p_tenant_id,
        'run_id',p_run_id,
        'decision',p_decision,
        'reason_code',p_reason_code,
        'risk_level',p_risk_level,
        'destructive',p_destructive,
        'approval_required',p_approval_required,
        'approval_ref',p_approval_ref,
        'policy_version',p_policy_version,
        'policy_hash',p_policy_hash,
        'kill_switch_version',p_kill_switch_version,
        'actor',p_actor,
        'correlation_id',p_correlation_id
      )::text,'UTF8'
    ),'sha256'
  ),'hex')
$$;

-- One authoritative kill-switch mutation boundary. A release always increments
-- the version too, so a stale worker cannot safely reuse an older decision.
create or replace function public.ai_engage_kill(
  p_scope text,
  p_scope_id text default null,
  p_reason text default null,
  p_actor text default 'system',
  p_metadata jsonb default '{}'::jsonb
) returns public.ai_kill_switches
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_kill_switches;
begin
  if p_scope not in ('GLOBAL','TENANT','AGENT','MISSION','PROVIDER','TOOL')
     or (p_scope='GLOBAL' and p_scope_id is not null)
     or (p_scope<>'GLOBAL' and p_scope_id is null) then
    raise exception 'invalid_kill_switch_scope';
  end if;

  insert into public.ai_kill_switches(
    scope,scope_id,engaged,reason,engaged_by,engaged_at,
    released_by,released_at,version,metadata,updated_at
  )
  values (
    p_scope,p_scope_id,true,left(p_reason,2000),left(p_actor,128),now(),
    null,null,1,coalesce(p_metadata,'{}'::jsonb),now()
  )
  on conflict (scope,scope_id) do update
    set engaged=true,
        reason=excluded.reason,
        engaged_by=excluded.engaged_by,
        engaged_at=excluded.engaged_at,
        released_by=null,
        released_at=null,
        version=ai_kill_switches.version+1,
        metadata=excluded.metadata,
        updated_at=now()
  returning * into r;

  return r;
end;
$$;

create or replace function public.ai_release_kill(
  p_scope text,
  p_scope_id text default null,
  p_actor text default 'system'
) returns public.ai_kill_switches
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_kill_switches;
begin
  select * into r
    from public.ai_kill_switches
   where scope=p_scope and scope_id is not distinct from p_scope_id
   for update;

  if not found then
    raise exception 'kill_switch_not_found';
  end if;

  update public.ai_kill_switches
     set engaged=false,
         released_by=left(p_actor,128),
         released_at=now(),
         version=version+1,
         updated_at=now()
   where id=r.id
   returning * into r;

  return r;
end;
$$;

-- Canonical fail-closed kill check. GLOBAL is checked first, then all
-- applicable scoped switches. No wildcard interpretation is performed.
create or replace function public.ai_is_frozen(
  p_tenant_id uuid,
  p_agent_id uuid,
  p_mission_id text,
  p_provider_id text,
  p_tool_id text
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_kill_switches;
begin
  for r in
    select *
      from public.ai_kill_switches
     where engaged=true
       and (
         (scope='GLOBAL' and scope_id is null)
         or (scope='TENANT' and scope_id=p_tenant_id::text)
         or (scope='AGENT' and scope_id=p_agent_id::text)
         or (scope='MISSION' and scope_id=p_mission_id)
         or (scope='PROVIDER' and scope_id=p_provider_id)
         or (scope='TOOL' and scope_id=p_tool_id)
       )
     order by case scope
       when 'GLOBAL' then 1 when 'TENANT' then 2 when 'AGENT' then 3
       when 'MISSION' then 4 when 'PROVIDER' then 5 when 'TOOL' then 6
     end
     for update
  loop
    return jsonb_build_object(
      'frozen',true,
      'scope',r.scope,
      'scope_id',r.scope_id,
      'version',r.version,
      'reason',coalesce(r.reason,'kill_switch_engaged')
    );
  end loop;

  return jsonb_build_object('frozen',false);
end;
$$;

-- Single execution-security decision boundary. It derives tenant identity from
-- the durable run and refuses caller-supplied tenant context.
create or replace function public.ai_security_admit(
  p_run_id uuid,
  p_agent_id uuid,
  p_mission_id text,
  p_provider_id text,
  p_tool_id text,
  p_risk_level text,
  p_destructive boolean default false,
  p_approval_ref text default null,
  p_policy_version text default null,
  p_policy_hash text default null,
  p_actor text default 'system'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  v_run public.ai_runs;
  v_freeze jsonb;
  v_decision text;
  v_reason text;
  v_approval boolean;
  v_hash text;
  v_corr text;
  v_kill_version bigint;
begin
  select * into v_run
    from public.ai_runs
   where id=p_run_id
   for update;

  if not found then
    raise exception 'run_not_found';
  end if;

  if p_agent_id is null or p_mission_id is null or p_provider_id is null
     or p_tool_id is null
     or p_risk_level not in ('LOW','MEDIUM','HIGH','CRITICAL') then
    raise exception 'invalid_security_context';
  end if;

  if v_run.agent_id <> p_agent_id
     or v_run.mission_id <> p_mission_id
     or v_run.provider_id <> p_provider_id then
    raise exception 'security_context_mismatch';
  end if;

  v_corr := coalesce(v_run.correlation_id,v_run.trace_id,v_run.id::text);

  v_freeze := public.ai_is_frozen(
    v_run.tenant_id,p_agent_id,p_mission_id,p_provider_id,p_tool_id
  );

  if coalesce((v_freeze->>'frozen')::boolean,false) then
    v_decision := 'DENY';
    v_reason := 'KILL_SWITCH';
    v_approval := false;
    v_kill_version := (v_freeze->>'version')::bigint;
  elsif p_destructive and p_approval_ref is null then
    v_decision := 'APPROVAL_REQUIRED';
    v_reason := 'DESTRUCTIVE_ACTION_REQUIRES_APPROVAL';
    v_approval := true;
    v_kill_version := null;
  else
    v_decision := 'ALLOW';
    v_reason := 'SECURITY_POLICY_ALLOWED';
    v_approval := false;
    v_kill_version := null;
  end if;

  v_hash := public.ai_security_decision_hash(
    v_run.tenant_id,v_run.id,v_decision,v_reason,p_risk_level,
    p_destructive,v_approval,p_approval_ref,p_policy_version,p_policy_hash,
    v_kill_version,left(p_actor,128),v_corr
  );

  insert into public.ai_security_decisions(
    tenant_id,run_id,decision,reason_code,risk_level,destructive,
    approval_required,approval_ref,policy_version,policy_hash,
    kill_switch_version,actor,correlation_id,decision_hash
  )
  values (
    v_run.tenant_id,v_run.id,v_decision,v_reason,p_risk_level,p_destructive,
    v_approval,p_approval_ref,p_policy_version,p_policy_hash,
    v_kill_version,left(p_actor,128),v_corr,v_hash
  );

  return jsonb_build_object(
    'allowed',v_decision='ALLOW',
    'decision',v_decision,
    'reason_code',v_reason,
    'approval_required',v_approval,
    'decision_hash',v_hash,
    'kill_switch_version',v_kill_version
  );
end;
$$;

-- Browser clients cannot mutate security state or call the decision boundary.
alter table public.ai_kill_switches enable row level security;
alter table public.ai_security_decisions enable row level security;

revoke all on table public.ai_kill_switches,public.ai_security_decisions
  from anon,authenticated;

revoke all on function public.ai_engage_kill(text,text,text,text,jsonb)
  from public,anon,authenticated;
revoke all on function public.ai_release_kill(text,text,text)
  from public,anon,authenticated;
revoke all on function public.ai_is_frozen(uuid,uuid,text,text,text)
  from public,anon,authenticated;
revoke all on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text)
  from public,anon,authenticated;
revoke all on function public.ai_security_decision_hash(uuid,uuid,text,text,text,boolean,boolean,text,text,text,bigint,text,text)
  from public,anon,authenticated;

grant execute on function public.ai_engage_kill(text,text,text,text,jsonb) to service_role;
grant execute on function public.ai_release_kill(text,text,text) to service_role;
grant execute on function public.ai_is_frozen(uuid,uuid,text,text,text) to service_role;
grant execute on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text) to service_role;
grant execute on function public.ai_security_decision_hash(uuid,uuid,text,text,text,boolean,boolean,text,text,text,bigint,text,text) to service_role;

comment on table public.ai_security_decisions is
'Append-only execution security decision ledger. Every allow, deny, and approval-required decision receives a reproducible SHA-256 decision hash.';

comment on table public.ai_kill_switches is
'Canonical hierarchical AI execution freeze state. GLOBAL, tenant, agent, mission, provider, and tool switches are evaluated fail-closed.';

comment on function public.ai_security_admit is
'Canonical AI security decision boundary. Derives tenant from the durable run, validates execution identity, checks kill switches, and blocks destructive actions without approval.';
