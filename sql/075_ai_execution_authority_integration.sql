-- 075_ai_execution_authority_integration.sql
-- Integrate the canonical security decision, resource admission and exact
-- execution identity without introducing a second execution engine.

alter table public.ai_runs
  add column if not exists tool_id text,
  add column if not exists tool_version integer;

alter table public.ai_runs
  drop constraint if exists ai_runs_tool_version_check;
alter table public.ai_runs
  add constraint ai_runs_tool_version_check
  check (tool_version is null or tool_version > 0);

create index if not exists idx_ai_runs_tool
  on public.ai_runs(tenant_id,tool_id,tool_version)
  where tool_id is not null;

-- The tool is part of the durable run identity. Existing callers that have not
-- yet populated it remain compatible; new authoritative execution paths must.
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
  v_decision_id bigint;
begin
  select * into v_run
    from public.ai_runs
   where id=p_run_id
   for update;

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

revoke all on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text)
  from public,anon,authenticated;
grant execute on function public.ai_security_admit(uuid,uuid,text,text,text,text,boolean,text,text,text,text)
  to service_role;

-- One privileged transaction boundary for security + resource admission.
-- It does not dispatch commands; case_actions/commands remain the response
-- authority and the Python orchestrator remains the execution coordinator.
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
  p_lease_seconds integer default 600
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
  select * into v_run
    from public.ai_runs
   where id=p_run_id
   for update;

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
    p_policy_version,p_policy_hash,p_actor
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

revoke all on function public.ai_authorize_execution(uuid,uuid,text,text,text,text,text,boolean,numeric,text,text,text,text,integer)
  from public,anon,authenticated;
grant execute on function public.ai_authorize_execution(uuid,uuid,text,text,text,text,text,boolean,numeric,text,text,text,text,integer)
  to service_role;

comment on function public.ai_authorize_execution is
'Canonical privileged execution admission: security decision first, then atomic rate/concurrency/budget admission. It never dispatches a command.';
