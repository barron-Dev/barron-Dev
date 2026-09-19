-- 085_workforce_ai_execution_authority.sql
-- Complete the Workforce AI path through the existing canonical execution
-- authority. No workforce-specific model/provider/tool authorization is added.

create or replace function workforce.authorize_ai_turn_execution(
  p_user_id uuid,
  p_turn_id uuid,
  p_run_id uuid,
  p_execution_config jsonb,
  p_risk_level text,
  p_destructive boolean default false,
  p_estimated_cost_usd numeric(18,8) default 0,
  p_approval_ref text default null,
  p_action_hash text default null,
  p_actor text default 'workforce_ai',
  p_lease_seconds integer default 600
)
returns jsonb
language plpgsql
security definer
set search_path = workforce, public, pg_catalog
as $$
declare
  v_employee workforce.employees%rowtype;
  v_turn workforce.ai_turns%rowtype;
  v_run public.ai_runs%rowtype;
  v_auth jsonb;
  v_commit jsonb;
begin
  if p_user_id is null or p_turn_id is null or p_run_id is null
     or p_execution_config is null
     or p_risk_level not in ('LOW','MEDIUM','HIGH','CRITICAL')
     or p_estimated_cost_usd is null or p_estimated_cost_usd < 0
     or p_lease_seconds not between 30 and 3600 then
    raise exception 'invalid_workforce_execution_request';
  end if;

  select * into v_employee
    from workforce.employees
   where user_id = p_user_id
   for update;

  if not found or v_employee.status <> 'active' then
    raise exception 'workforce_employee_not_active';
  end if;

  select * into v_turn
    from workforce.ai_turns
   where id = p_turn_id
   for update;

  if not found then
    raise exception 'ai_turn_not_found';
  end if;

  if v_turn.employee_id <> v_employee.id then
    raise exception 'workforce_ai_turn_owner_mismatch';
  end if;

  if v_turn.status <> 'accepted' then
    raise exception 'ai_turn_not_executable';
  end if;

  select * into v_run
    from public.ai_runs
   where id = p_run_id
   for update;

  if not found then
    raise exception 'ai_run_not_found';
  end if;

  if v_run.tenant_id <> v_turn.tenant_id
     or v_run.mission_id <> v_turn.mission_id::text
     or v_run.mission_version <> v_turn.mission_version
     or v_run.mission_hash <> v_turn.mission_hash then
    raise exception 'workforce_ai_execution_identity_mismatch';
  end if;

  if v_turn.ai_run_id is null then
    update workforce.ai_turns
       set ai_run_id = v_run.id
     where id = v_turn.id;
  elsif v_turn.ai_run_id <> v_run.id then
    raise exception 'ai_turn_already_bound_to_different_run';
  end if;

  v_commit := public.ai_authorize_and_commit_execution(
    v_run.id,
    v_run.agent_id,
    v_run.mission_id,
    v_run.model_id,
    v_run.provider_id,
    v_run.tool_id,
    p_risk_level,
    p_destructive,
    p_estimated_cost_usd,
    p_execution_config,
    v_run.agent_version,
    v_run.mission_version,
    v_run.mission_hash,
    v_run.model_version,
    v_run.provider_binding_version,
    v_run.tool_version,
    p_approval_ref,
    v_run.policy_version,
    v_run.policy_hash,
    v_run.playbook_version,
    v_run.playbook_hash,
    v_run.twin_version,
    v_run.twin_hash,
    null,
    null,
    left(p_actor,128),
    p_lease_seconds,
    p_action_hash
  );

  if coalesce((v_commit->>'allowed')::boolean,false) is not true then
    return jsonb_build_object(
      'allowed',false,
      'turn_id',v_turn.id,
      'run_id',v_run.id,
      'decision',v_commit->>'decision',
      'reason_code',v_commit->>'reason_code',
      'approval_required',coalesce((v_commit->>'approval_required')::boolean,false),
      'decision_id',v_commit->>'decision_id'
    );
  end if;

  return v_commit || jsonb_build_object(
    'allowed',true,
    'turn_id',v_turn.id,
    'run_id',v_run.id,
    'decision_id',v_auth->>'decision_id'
  );
exception
  when others then
    raise;
end;
$$;

revoke all on function workforce.authorize_ai_turn_execution(
  uuid,uuid,uuid,jsonb,text,boolean,numeric,text,text,text,integer
) from public, anon, authenticated;

grant execute on function workforce.authorize_ai_turn_execution(
  uuid,uuid,uuid,jsonb,text,boolean,numeric,text,text,text,integer
) to service_role;


create or replace function workforce.complete_ai_turn_execution(
  p_user_id uuid,
  p_turn_id uuid,
  p_output_hash text,
  p_status text default 'completed',
  p_actual_cost_usd numeric(18,8) default 0
)
returns jsonb
language plpgsql
security definer
set search_path = workforce, public, pg_catalog
as $$
declare
  v_employee workforce.employees%rowtype;
  v_turn workforce.ai_turns%rowtype;
  v_completed boolean;
begin
  if p_user_id is null or p_turn_id is null
     or p_output_hash is null
     or p_output_hash !~ '^[0-9a-f]{64}$'
     or p_status not in ('completed','rejected','failed')
     or p_actual_cost_usd is null or p_actual_cost_usd < 0 then
    raise exception 'invalid_workforce_completion';
  end if;

  select * into v_employee
    from workforce.employees
   where user_id = p_user_id
   for update;

  if not found then
    raise exception 'workforce_employee_not_found';
  end if;

  select * into v_turn
    from workforce.ai_turns
   where id = p_turn_id
   for update;

  if not found or v_turn.employee_id <> v_employee.id then
    raise exception 'workforce_ai_turn_owner_mismatch';
  end if;

  if v_turn.ai_run_id is null then
    raise exception 'ai_turn_run_not_bound';
  end if;

  v_completed := workforce.complete_ai_turn(
    p_turn_id,p_output_hash,p_status
  );

  if p_status = 'completed' and v_completed then
    perform public.ai_settle_execution(v_turn.ai_run_id,p_actual_cost_usd);
  else
    perform public.ai_release_execution(v_turn.ai_run_id);
  end if;

  return jsonb_build_object(
    'completed',v_completed,
    'turn_id',v_turn.id,
    'run_id',v_turn.ai_run_id,
    'status',case when v_completed then p_status else 'failed' end
  );
end;
$$;

revoke all on function workforce.complete_ai_turn_execution(
  uuid,uuid,text,text,numeric
) from public, anon, authenticated;

grant execute on function workforce.complete_ai_turn_execution(
  uuid,uuid,text,text,numeric
) to service_role;

comment on function workforce.authorize_ai_turn_execution is
'Workforce AI execution bridge. Employee/turn identity is checked here, then the existing public.ai_authorize_execution and public.ai_execution_commit remain authoritative.';

comment on function workforce.complete_ai_turn_execution is
'Workforce AI completion bridge. Completion settles successful canonical admission and releases failed/rejected execution resources.';
