-- 077_ai_execution_commit_guard.sql
-- Finalize the admission/provenance boundary: execution cannot become
-- dispatchable unless the security decision, resource admission and exact
-- provenance snapshot all agree.

create or replace function public.ai_execution_commit(
  p_run_id uuid,
  p_security_decision_id bigint,
  p_execution_config jsonb,
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
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  r public.ai_runs;
  d public.ai_security_decisions;
  p public.ai_execution_provenance;
  cfg_hash text;
begin
  select * into r from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  select * into d
    from public.ai_security_decisions
   where id=p_security_decision_id
     and tenant_id=r.tenant_id
     and run_id=r.id
   for update;

  if not found or d.decision <> 'ALLOW' then
    raise exception 'execution_not_authorized';
  end if;

  if r.tool_id is not null and r.tool_id <> p_tool_id then
    raise exception 'tool_identity_mismatch';
  end if;

  cfg_hash := public.ai_hash_execution_config(p_execution_config);

  p := public.ai_bind_execution_provenance(
    r.id,d.id,p_execution_config,cfg_hash,
    p_agent_version,p_mission_id,p_mission_version,p_mission_hash,
    p_model_id,p_model_version,p_provider_id,p_provider_binding_version,
    p_tool_id,p_tool_version,p_policy_version,p_policy_hash,
    p_playbook_version,p_playbook_hash,p_twin_version,p_twin_hash,
    p_envelope_id,p_envelope_hash,p_admission_hash
  );

  if p.admission_hash is null and p_admission_hash is not null then
    raise exception 'admission_binding_failed';
  end if;

  return jsonb_build_object(
    'committed',true,
    'run_id',r.id,
    'tenant_id',r.tenant_id,
    'security_decision_id',d.id,
    'security_decision_hash',d.decision_hash,
    'execution_config_hash',p.execution_config_hash,
    'envelope_id',p.envelope_id,
    'envelope_hash',p.envelope_hash,
    'admission_hash',p.admission_hash
  );
end;
$$;

-- The commit boundary is privileged only.
revoke all on function public.ai_execution_commit(
  uuid,bigint,jsonb,integer,text,integer,text,text,integer,text,integer,text,integer,
  text,text,text,text,text,text,text,text,text
) from public,anon,authenticated;

grant execute on function public.ai_execution_commit(
  uuid,bigint,jsonb,integer,text,integer,text,text,integer,text,integer,text,integer,
  text,text,text,text,text,text,text,text,text
) to service_role;

comment on function public.ai_execution_commit is
'Fail-closed execution commit. It binds an already-allowed run to one exact configuration/provenance snapshot before downstream execution.';
