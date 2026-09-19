-- 091_workforce_execution_outcome_unification.sql
-- Unify Workforce AI completion with the canonical execution outcome boundary.
-- This removes the last parallel settle/release path.

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
  v_outcome text;
  v_execution jsonb;
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
    p_turn_id,
    p_output_hash,
    p_status
  );

  if not v_completed then
    raise exception 'workforce_ai_turn_completion_denied';
  end if;

  v_outcome := case
    when p_status = 'completed' then 'COMPLETED'
    when p_status = 'rejected' then 'REJECTED'
    else 'FAILED'
  end;

  v_execution := public.ai_complete_execution(
    v_turn.ai_run_id,
    v_outcome,
    p_actual_cost_usd,
    case
      when p_status = 'completed' then null
      else jsonb_build_object(
        'source','workforce_ai',
        'turn_id',v_turn.id,
        'status',p_status
      )
    end,
    'workforce_ai'
  );

  return v_execution || jsonb_build_object(
    'completed',true,
    'turn_id',v_turn.id,
    'run_id',v_turn.ai_run_id,
    'status',p_status
  );
end;
$$;

revoke all on function workforce.complete_ai_turn_execution(
  uuid,uuid,text,text,numeric
) from public, anon, authenticated;

grant execute on function workforce.complete_ai_turn_execution(
  uuid,uuid,text,text,numeric
) to service_role;

comment on function workforce.complete_ai_turn_execution is
'Workforce AI completion uses the single canonical public.ai_complete_execution outcome boundary for settlement, release, and terminal run transition.';
