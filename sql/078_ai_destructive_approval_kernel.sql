-- 078_ai_destructive_approval_kernel.sql
-- Replace loose approval references with an authoritative, one-time,
-- run-bound approval record. Destructive execution remains fail-closed.

create table if not exists public.ai_execution_approvals (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  approval_ref text not null,
  action_hash text not null check (action_hash ~ '^[0-9a-f]{64}$'),
  risk_level text not null check (risk_level in ('LOW','MEDIUM','HIGH','CRITICAL')),
  approver text not null,
  approved_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  metadata jsonb not null default '{}'::jsonb,
  unique (tenant_id,approval_ref),
  check (expires_at > approved_at)
);

create index if not exists idx_ai_execution_approvals_run
  on public.ai_execution_approvals(tenant_id,run_id,expires_at);

create unique index if not exists uq_ai_execution_approval_active_run
  on public.ai_execution_approvals(run_id,action_hash)
  where consumed_at is null;

create or replace function public.ai_create_execution_approval(
  p_run_id uuid,
  p_approval_ref text,
  p_action_hash text,
  p_risk_level text,
  p_approver text,
  p_expires_at timestamptz,
  p_metadata jsonb default '{}'::jsonb
) returns public.ai_execution_approvals
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  r public.ai_runs;
  a public.ai_execution_approvals;
begin
  if p_run_id is null
     or p_approval_ref is null or length(trim(p_approval_ref))=0 or length(p_approval_ref)>128
     or p_action_hash is null or p_action_hash !~ '^[0-9a-f]{64}$'
     or p_risk_level not in ('LOW','MEDIUM','HIGH','CRITICAL')
     or p_approver is null or length(trim(p_approver))=0 or length(p_approver)>128
     or p_expires_at <= now() then
    raise exception 'invalid_execution_approval';
  end if;

  select * into r from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  insert into public.ai_execution_approvals(
    tenant_id,run_id,approval_ref,action_hash,risk_level,
    approver,approved_at,expires_at,metadata
  ) values (
    r.tenant_id,r.id,p_approval_ref,p_action_hash,p_risk_level,
    left(p_approver,128),now(),p_expires_at,coalesce(p_metadata,'{}'::jsonb)
  )
  returning * into a;

  return a;
end;
$$;

-- Validate and atomically consume an approval. A consumed approval can never
-- authorize a second destructive execution.
create or replace function public.ai_consume_execution_approval(
  p_run_id uuid,
  p_approval_ref text,
  p_action_hash text,
  p_risk_level text
) returns public.ai_execution_approvals
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  r public.ai_runs;
  a public.ai_execution_approvals;
begin
  if p_run_id is null or p_approval_ref is null
     or p_action_hash is null or p_action_hash !~ '^[0-9a-f]{64}$'
     or p_risk_level not in ('LOW','MEDIUM','HIGH','CRITICAL') then
    raise exception 'invalid_execution_approval';
  end if;

  select * into r from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  select * into a
    from public.ai_execution_approvals
   where tenant_id=r.tenant_id
     and run_id=r.id
     and approval_ref=p_approval_ref
   for update;

  if not found then raise exception 'approval_not_found'; end if;

  if a.consumed_at is not null then
    raise exception 'approval_already_consumed';
  end if;

  if a.expires_at <= now() then
    raise exception 'approval_expired';
  end if;

  if a.action_hash <> p_action_hash or a.risk_level <> p_risk_level then
    raise exception 'approval_context_mismatch';
  end if;

  update public.ai_execution_approvals
     set consumed_at=now()
   where id=a.id
   returning * into a;

  return a;
end;
$$;

-- The security decision now requires an actual approval record for destructive
-- execution. The approval reference alone is never sufficient.
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
  p_actor text default 'system',
  p_action_hash text default null
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
  v_decision_id bigint;
begin
  select * into v_run from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  if p_agent_id is null or p_mission_id is null or p_provider_id is null
     or p_tool_id is null
     or p_risk_level not in ('LOW','MEDIUM','HIGH','CRITICAL') then
    raise exception 'invalid_security_context';
  end if;

  if v_run.agent_id <> p_agent_id
     or v_run.mission_id <> p_mission_id
     or v_run.provider_id <> p_provider_id
     or (v_run.tool_id is not null and v_run.tool_id <> p_tool_id) then
    raise exception 'security_context_mismatch';
  end if;

  v_corr := coalesce(v_run.correlation_id,v_run.trace_id,v_run.id::text);
  v_freeze := public.ai_is_frozen(v_run.tenant_id,p_agent_id,p_mission_id,p_provider_id,p_tool_id);

  if coalesce((v_freeze->>'frozen')::boolean,false) then
    v_decision := 'DENY';
    v_reason := 'KILL_SWITCH';
    v_approval := false;
    v_kill_version := (v_freeze->>'version')::bigint;
  elsif p_destructive then
    if p_approval_ref is null or p_action_hash is null
       or p_action_hash !~ '^[0-9a-f]{64}$' then
      v_decision := 'APPROVAL_REQUIRED';
      v_reason := 'DESTRUCTIVE_ACTION_REQUIRES_APPROVAL';
      v_approval := true;
      v_kill_version := null;
    else
      -- Validate the approval before allowing the security decision.
      perform public.ai_consume_execution_approval(
        p_run_id,p_approval_ref,p_action_hash,p_risk_level
      );
      v_decision := 'ALLOW';
      v_reason := 'APPROVED_DESTRUCTIVE_ACTION';
      v_approval := false;
      v_kill_version := null;
    end if;
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
  ) values (
    v_run.tenant_id,v_run.id,v_decision,v_reason,p_risk_level,p_destructive,
    v_approval,p_approval_ref,p_policy_version,p_policy_hash,
    v_kill_version,left(p_actor,128),v_corr,v_hash
  ) returning id into v_decision_id;

  return jsonb_build_object(
    'allowed',v_decision='ALLOW',
    'decision',v_decision,
    'decision_id',v_decision_id,
    'reason_code',v_reason,
    'approval_required',v_approval,
    'decision_hash',v_hash,
    'kill_switch_version',v_kill_version
  );
end;
$$;

-- Replace the unified authority signature so destructive approvals carry the
-- exact action hash into the security boundary.
drop function if exists public.ai_authorize_execution(
  uuid,uuid,text,text,text,text,text,boolean,numeric,text,text,text,text,integer
);

create or replace function public.ai_authorize_execution(
  p_run_id uuid,
  p_agent_id uuid,
  p_mission_id text,
  p_model_id text,
  p_provider_id text,
  p_tool_id text,
  p_risk_level text,
  p_destructive boolean,
  p_estimated_cost_usd numeric(18,8),
  p_approval_ref text default null,
  p_policy_version text default null,
  p_policy_hash text default null,
  p_actor text default 'system',
  p_lease_seconds integer default 600,
  p_action_hash text default null
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  v_run public.ai_runs;
  v_security jsonb;
  v_admission jsonb;
begin
  select * into v_run from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  if v_run.agent_id <> p_agent_id
     or v_run.mission_id <> p_mission_id
     or v_run.model_id <> p_model_id
     or v_run.provider_id <> p_provider_id
     or (v_run.tool_id is not null and v_run.tool_id <> p_tool_id) then
    raise exception 'execution_identity_mismatch';
  end if;

  v_security := public.ai_security_admit(
    p_run_id,p_agent_id,p_mission_id,p_provider_id,p_tool_id,
    p_risk_level,p_destructive,p_approval_ref,
    p_policy_version,p_policy_hash,p_actor,p_action_hash
  );

  if coalesce((v_security->>'allowed')::boolean,false) is not true then
    return jsonb_build_object(
      'allowed',false,
      'decision',v_security->>'decision',
      'decision_id',v_security->>'decision_id',
      'decision_hash',v_security->>'decision_hash',
      'reason_code',v_security->>'reason_code',
      'approval_required',coalesce((v_security->>'approval_required')::boolean,false)
    );
  end if;

  v_admission := public.ai_admit_execution(
    v_run.tenant_id,p_run_id,p_agent_id,p_mission_id,p_model_id,
    p_provider_id,p_tool_id,p_estimated_cost_usd,p_lease_seconds
  );

  if coalesce((v_admission->>'ok')::boolean,false) is not true then
    return jsonb_build_object(
      'allowed',false,
      'decision','ADMISSION_DENIED',
      'decision_id',v_security->>'decision_id',
      'decision_hash',v_security->>'decision_hash',
      'reason_code',v_admission->>'reason',
      'security_decision','ALLOW',
      'admission',v_admission
    );
  end if;

  return jsonb_build_object(
    'allowed',true,
    'decision','ALLOW',
    'decision_id',v_security->>'decision_id',
    'decision_hash',v_security->>'decision_hash',
    'admission',v_admission
  );
end;
$$;

do $$
begin
  revoke all on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text)
    from public,anon,authenticated;
  revoke all on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text,text)
    from public,anon,authenticated;
  revoke all on function public.ai_create_execution_approval(uuid,text,text,text,text,timestamptz,jsonb)
    from public,anon,authenticated;
  revoke all on function public.ai_consume_execution_approval(uuid,text,text,text)
    from public,anon,authenticated;
  revoke all on function public.ai_authorize_execution(uuid,uuid,text,text,text,text,text,boolean,numeric,text,text,text,text,integer,text)
    from public,anon,authenticated;
end $$;

grant execute on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text,text) to service_role;
grant execute on function public.ai_create_execution_approval(uuid,text,text,text,text,timestamptz,jsonb) to service_role;
grant execute on function public.ai_consume_execution_approval(uuid,text,text,text) to service_role;
grant execute on function public.ai_authorize_execution(uuid,uuid,text,text,text,text,text,boolean,numeric,text,text,text,text,integer,text) to service_role;

alter table public.ai_execution_approvals enable row level security;
revoke all on table public.ai_execution_approvals from anon,authenticated;

comment on table public.ai_execution_approvals is
'One-time, run-bound destructive execution approvals. Approval references alone cannot authorize execution.';
