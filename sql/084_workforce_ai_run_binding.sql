-- 084_workforce_ai_run_binding.sql
-- Bind an admitted workforce AI turn to one canonical public.ai_runs execution.
-- This creates a durable relationship; it does not create a second execution
-- authority. Canonical execution admission remains public.ai_authorize_execution.

alter table workforce.ai_turns
  add column if not exists ai_run_id uuid references public.ai_runs(id) on delete restrict;

create unique index if not exists workforce_ai_turns_ai_run_uidx
  on workforce.ai_turns(ai_run_id)
  where ai_run_id is not null;

create index if not exists workforce_ai_turns_run_idx
  on workforce.ai_turns(ai_run_id)
  where ai_run_id is not null;

create or replace function workforce.bind_ai_turn_run(
  p_turn_id uuid,
  p_run_id uuid
)
returns table (
  allowed boolean,
  turn_id uuid,
  run_id uuid,
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
  v_turn workforce.ai_turns%rowtype;
  v_run public.ai_runs%rowtype;
begin
  if p_turn_id is null or p_run_id is null then
    return query select false, null::uuid, null::uuid, null::uuid,
      null::uuid, null::integer, null::text, 'invalid_ai_run_binding';
    return;
  end if;

  select *
    into v_turn
    from workforce.ai_turns
   where id = p_turn_id
   for update;

  if not found then
    return query select false, null::uuid, null::uuid, null::uuid,
      null::uuid, null::integer, null::text, 'ai_turn_not_found';
    return;
  end if;

  if v_turn.status <> 'accepted' then
    return query select false, v_turn.id, null::uuid, v_turn.tenant_id,
      v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
      'ai_turn_not_bindable';
    return;
  end if;

  if v_turn.ai_run_id is not null then
    if v_turn.ai_run_id = p_run_id then
      return query select true, v_turn.id, v_turn.ai_run_id, v_turn.tenant_id,
        v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
        'already_bound';
    end if;

    return query select false, v_turn.id, v_turn.ai_run_id, v_turn.tenant_id,
      v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
      'ai_turn_already_bound';
    return;
  end if;

  select *
    into v_run
    from public.ai_runs
   where id = p_run_id
   for update;

  if not found then
    return query select false, v_turn.id, null::uuid, v_turn.tenant_id,
      v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
      'ai_run_not_found';
    return;
  end if;

  if v_run.tenant_id <> v_turn.tenant_id
     or v_run.mission_id <> v_turn.mission_id::text then
    return query select false, v_turn.id, v_run.id, v_turn.tenant_id,
      v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
      'ai_run_mission_mismatch';
    return;
  end if;

  update workforce.ai_turns
     set ai_run_id = v_run.id
   where id = v_turn.id;

  return query select true, v_turn.id, v_run.id, v_turn.tenant_id,
    v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
    'bound';
exception
  when unique_violation then
    return query select false, p_turn_id, null::uuid, v_turn.tenant_id,
      v_turn.mission_id, v_turn.mission_version, v_turn.mission_hash,
      'ai_run_already_bound';
end;
$$;

revoke all on function workforce.bind_ai_turn_run(uuid,uuid)
  from public, anon, authenticated;

grant execute on function workforce.bind_ai_turn_run(uuid,uuid)
  to service_role;

comment on function workforce.bind_ai_turn_run is
'Durably binds an admitted workforce AI turn to one canonical public.ai_runs record; execution authority remains public.ai_authorize_execution.';
