-- 089_execution_outcome_settlement.sql
-- Close the execution lifecycle through one idempotent, server-authoritative
-- outcome boundary. Dispatchers report facts; the database owns settlement.

create or replace function public.ai_complete_execution(
  p_run_id uuid,
  p_outcome text,
  p_actual_cost_usd numeric(18,8) default 0,
  p_error jsonb default null,
  p_actor text default 'system'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r public.ai_runs;
  v_committed boolean;
begin
  if p_run_id is null
     or p_outcome not in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED')
     or p_actual_cost_usd is null
     or p_actual_cost_usd < 0 then
    raise exception 'invalid_execution_outcome';
  end if;

  select * into r
    from public.ai_runs
   where id = p_run_id
   for update;

  if not found then
    raise exception 'run_not_found';
  end if;

  select exists (
    select 1
      from public.ai_execution_provenance p
     where p.run_id = r.id
  ) into v_committed;

  if not v_committed then
    raise exception 'execution_not_committed';
  end if;

  if r.run_state in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED') then
    if r.run_state <> p_outcome then
      raise exception 'execution_already_finalized';
    end if;

    return jsonb_build_object(
      'completed',true,
      'idempotent',true,
      'run_id',r.id,
      'run_state',r.run_state,
      'cost_usd',r.cost_usd
    );
  end if;

  if p_outcome = 'COMPLETED' then
    perform public.ai_settle_execution(r.id,p_actual_cost_usd);
    perform public.ai_transition_run(r.id,'COMPLETED',coalesce(p_actor,'system'));
  else
    perform public.ai_release_execution(r.id);
    perform public.ai_transition_run(r.id,p_outcome,coalesce(p_actor,'system'));
  end if;

  if p_error is not null then
    update public.ai_runs
       set error = p_error
     where id = r.id;
  end if;

  select * into r from public.ai_runs where id=r.id;

  return jsonb_build_object(
    'completed',true,
    'idempotent',false,
    'run_id',r.id,
    'run_state',r.run_state,
    'cost_usd',r.cost_usd
  );
end;
$$;

revoke all on function public.ai_complete_execution(
  uuid,text,numeric,jsonb,text
) from public,anon,authenticated;
grant execute on function public.ai_complete_execution(
  uuid,text,numeric,jsonb,text
) to service_role;

-- Bind the command lifecycle to its originating canonical AI run.
alter table public.commands
  add column if not exists completed_at timestamptz,
  add column if not exists outcome text,
  add column if not exists outcome_error jsonb;

create index if not exists idx_commands_ai_run_state
  on public.commands(ai_run_id, status)
  where ai_run_id is not null;

comment on function public.ai_complete_execution is
'Idempotent terminal execution boundary. Successful executions settle admitted resources; non-success outcomes release them before the canonical run transition.';
