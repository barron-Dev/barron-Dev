-- 092_execution_liveness_watchdog.sql
-- Durable watchdog for committed AI executions. Recovery is fail-closed:
-- a stale run is marked TIMEOUT and released through the canonical outcome
-- boundary. No second settlement mechanism is introduced.

create or replace function public.ai_recover_stale_execution(
  p_run_id uuid,
  p_actor text default 'execution_watchdog'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r public.ai_runs;
  v_age interval;
  v_timeout interval := interval '15 minutes';
  v_result jsonb;
begin
  if p_run_id is null then
    raise exception 'run_id_required';
  end if;

  select * into r
    from public.ai_runs
   where id=p_run_id
   for update;

  if not found then
    raise exception 'run_not_found';
  end if;

  if r.run_state in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED') then
    return jsonb_build_object(
      'recovered',false,
      'idempotent',true,
      'run_id',r.id,
      'run_state',r.run_state
    );
  end if;

  if r.run_state not in ('RUNNING','STREAMING','WAITING_APPROVAL','RECOVERING') then
    return jsonb_build_object(
      'recovered',false,
      'run_id',r.id,
      'run_state',r.run_state
    );
  end if;

  v_age := now() - coalesce(r.heartbeat_at,r.started_at,r.created_at);

  if v_age < v_timeout then
    return jsonb_build_object(
      'recovered',false,
      'run_id',r.id,
      'run_state',r.run_state,
      'reason','heartbeat_fresh'
    );
  end if;

  v_result := public.ai_complete_execution(
    r.id,
    'TIMEOUT',
    0,
    jsonb_build_object(
      'source','execution_watchdog',
      'reason','stale_heartbeat',
      'heartbeat_at',r.heartbeat_at,
      'observed_at',now()
    ),
    left(coalesce(p_actor,'execution_watchdog'),128)
  );

  return v_result || jsonb_build_object(
    'recovered',true,
    'reason','stale_heartbeat'
  );
end;
$$;

revoke all on function public.ai_recover_stale_execution(uuid,text)
  from public,anon,authenticated;
grant execute on function public.ai_recover_stale_execution(uuid,text)
  to service_role;

comment on function public.ai_recover_stale_execution is
'Fail-closed stale execution watchdog. Only the canonical ai_complete_execution boundary may release and transition the stale run.';
