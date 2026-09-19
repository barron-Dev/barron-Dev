-- 094_execution_outcome_boundary_hardening.sql
-- Corrective hardening for 093: preserve the established 089 terminal
-- execution semantics and append the immutable outcome ledger without
-- replacing the canonical boundary with a parallel implementation.

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
  v_outcome_id uuid;
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

    select id into v_outcome_id
      from public.ai_execution_outcomes
     where run_id = r.id;

    return jsonb_build_object(
      'completed',true,
      'idempotent',true,
      'run_id',r.id,
      'run_state',r.run_state,
      'cost_usd',r.cost_usd,
      'outcome_id',v_outcome_id
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

  insert into public.ai_execution_outcomes(
    run_id,tenant_id,outcome,actual_cost_usd,error,actor
  ) values (
    r.id,r.tenant_id,p_outcome,p_actual_cost_usd,p_error,
    left(coalesce(p_actor,'system'),128)
  )
  on conflict (run_id) do nothing
  returning id into v_outcome_id;

  if v_outcome_id is null then
    select id into v_outcome_id
      from public.ai_execution_outcomes
     where run_id=r.id;
  end if;

  return jsonb_build_object(
    'completed',true,
    'idempotent',false,
    'run_id',r.id,
    'run_state',r.run_state,
    'cost_usd',r.cost_usd,
    'outcome_id',v_outcome_id
  );
end;
$$;

revoke all on function public.ai_complete_execution(
  uuid,text,numeric,jsonb,text
) from public,anon,authenticated;
grant execute on function public.ai_complete_execution(
  uuid,text,numeric,jsonb,text
) to service_role;

comment on function public.ai_complete_execution is
'Canonical terminal execution boundary. Settlement/release and terminal transition remain authoritative here; immutable outcome audit is appended in the same transaction.';
