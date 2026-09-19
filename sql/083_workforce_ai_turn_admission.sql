-- 083_workforce_ai_turn_admission.sql
-- Workforce AI turn admission boundary.
-- GitHub-only: do not apply to production without explicit authorization.
-- Provider/model/tool selection is deliberately absent from the employee request.
-- The server resolves those from the approved mission execution configuration.

create or replace function workforce.admit_ai_turn(
  p_user_id uuid,
  p_session_id uuid,
  p_input_hash text,
  p_sequence_no bigint
)
returns table (
  allowed boolean,
  turn_id uuid,
  employee_id uuid,
  tenant_id uuid,
  mission_id uuid,
  mission_version integer,
  mission_hash text,
  reason text
)
language plpgsql
security definer
set search_path = workforce, pg_catalog
as $$
declare
  v_employee workforce.employees%rowtype;
  v_session workforce.ai_sessions%rowtype;
  v_assignment workforce.ai_mission_assignments%rowtype;
  v_mission record;
  v_turn_id uuid;
  v_next bigint;
begin
  if p_user_id is null
     or p_session_id is null
     or p_input_hash is null
     or p_input_hash !~ '^[0-9a-f]{64}$'
     or p_sequence_no is null
     or p_sequence_no < 1 then
    return query select false, null::uuid, null::uuid, null::uuid,
      null::uuid, null::integer, null::text, 'invalid_ai_turn_request';
    return;
  end if;

  select e.*
    into v_employee
    from workforce.employees e
   where e.user_id = p_user_id
   for update;

  if not found or v_employee.status <> 'active' then
    return query select false, coalesce(v_employee.id, null::uuid),
      coalesce(v_employee.id, null::uuid), null::uuid,
      null::uuid, null::integer, null::text, 'employee_not_active';
    return;
  end if;

  select s.*
    into v_session
    from workforce.ai_sessions s
   where s.id = p_session_id
     and s.employee_id = v_employee.id
   for update;

  if not found then
    return query select false, null::uuid, v_employee.id, null::uuid,
      null::uuid, null::integer, null::text, 'ai_session_not_found';
    return;
  end if;

  if v_session.status <> 'active' or v_session.expires_at <= now() then
    if v_session.status = 'active' and v_session.expires_at <= now() then
      update workforce.ai_sessions
         set status = 'expired'
       where id = v_session.id;
    end if;

    return query select false, null::uuid, v_employee.id, v_session.tenant_id,
      null::uuid, null::integer, null::text, 'ai_session_not_active';
    return;
  end if;

  select a.*
    into v_assignment
    from workforce.ai_mission_assignments a
   where a.id = v_session.mission_assignment_id
     and a.employee_id = v_employee.id
     and a.tenant_id = v_session.tenant_id
     and a.status = 'active'
     and a.valid_from <= now()
     and (a.valid_until is null or a.valid_until > now())
   for update;

  if not found then
    return query select false, null::uuid, v_employee.id, v_session.tenant_id,
      null::uuid, null::integer, null::text, 'ai_mission_assignment_not_active';
    return;
  end if;

  select m.id, m.tenant_id, m.version, m.compiled_hash, m.status
    into v_mission
    from public.ai_missions m
   where m.id = v_assignment.mission_id
     and m.tenant_id = v_assignment.tenant_id
     and m.version = v_assignment.mission_version
     and m.compiled_hash = v_assignment.mission_hash
     and m.status = 'active';

  if not found then
    return query select false, null::uuid, v_employee.id, v_session.tenant_id,
      v_assignment.mission_id, v_assignment.mission_version,
      v_assignment.mission_hash, 'ai_mission_not_active';
    return;
  end if;

  select coalesce(max(t.sequence_no), 0) + 1
    into v_next
    from workforce.ai_turns t
   where t.session_id = v_session.id;

  if p_sequence_no <> v_next then
    return query select false, null::uuid, v_employee.id, v_session.tenant_id,
      v_assignment.mission_id, v_assignment.mission_version,
      v_assignment.mission_hash, 'invalid_turn_sequence';
    return;
  end if;

  insert into workforce.ai_turns (
    session_id,
    employee_id,
    tenant_id,
    mission_id,
    mission_version,
    mission_hash,
    sequence_no,
    input_hash,
    status
  )
  values (
    v_session.id,
    v_employee.id,
    v_session.tenant_id,
    v_assignment.mission_id,
    v_assignment.mission_version,
    v_assignment.mission_hash,
    p_sequence_no,
    p_input_hash,
    'accepted'
  )
  returning id into v_turn_id;

  update workforce.ai_sessions
     set last_turn_at = now()
   where id = v_session.id;

  return query select true, v_turn_id, v_employee.id, v_session.tenant_id,
    v_assignment.mission_id, v_assignment.mission_version,
    v_assignment.mission_hash, 'allowed';
exception
  when unique_violation then
    return query select false, null::uuid, v_employee.id, v_session.tenant_id,
      v_assignment.mission_id, v_assignment.mission_version,
      v_assignment.mission_hash, 'turn_already_admitted';
end;
$$;

create or replace function workforce.complete_ai_turn(
  p_turn_id uuid,
  p_output_hash text,
  p_status text default 'completed'
)
returns boolean
language plpgsql
security definer
set search_path = workforce, pg_catalog
as $$
declare
  v_turn workforce.ai_turns%rowtype;
  v_employee workforce.employees%rowtype;
begin
  if p_turn_id is null
     or p_output_hash is null
     or p_output_hash !~ '^[0-9a-f]{64}$'
     or p_status not in ('completed','rejected','failed') then
    return false;
  end if;

  select * into v_turn
    from workforce.ai_turns
   where id = p_turn_id
   for update;

  if not found or v_turn.status <> 'accepted' then
    return false;
  end if;

  select * into v_employee
    from workforce.employees
   where id = v_turn.employee_id;

  -- A terminated/suspended employee cannot finalize a previously accepted turn.
  if not found or v_employee.status <> 'active' then
    update workforce.ai_turns
       set status = 'failed',
           output_hash = p_output_hash,
           completed_at = now()
     where id = p_turn_id;
    return false;
  end if;

  update workforce.ai_turns
     set status = p_status,
         output_hash = p_output_hash,
         completed_at = now()
   where id = p_turn_id;

  return true;
end;
$$;

revoke all on all routines in schema workforce from public, anon, authenticated;

grant execute on function workforce.admit_ai_turn(uuid,uuid,text,bigint)
  to service_role;

grant execute on function workforce.complete_ai_turn(uuid,text,text)
  to service_role;
