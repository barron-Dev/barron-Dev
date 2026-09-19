-- 103_ai_provider_usage_settlement.sql
-- Provider telemetry is attached to the canonical ai_runs row before terminal settlement.
create or replace function public.ai_record_provider_usage(
  p_run_id uuid,
  p_tokens_in bigint,
  p_tokens_out bigint,
  p_tokens_cached bigint default 0,
  p_latency_ms bigint default null,
  p_cost_usd numeric(18,8) default 0
) returns public.ai_runs
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r public.ai_runs;
begin
  if p_run_id is null
     or p_tokens_in < 0
     or p_tokens_out < 0
     or p_tokens_cached < 0
     or p_cost_usd < 0
     or (p_latency_ms is not null and p_latency_ms < 0) then
    raise exception 'invalid_provider_usage';
  end if;

  select * into r from public.ai_runs where id = p_run_id for update;
  if not found then
    raise exception 'run_not_found';
  end if;

  if r.run_state in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED') then
    raise exception 'execution_already_finalized';
  end if;

  update public.ai_runs
     set tokens_in = p_tokens_in,
         tokens_out = p_tokens_out,
         tokens_cached = p_tokens_cached,
         latency_ms = p_latency_ms,
         cost_usd = p_cost_usd
   where id = p_run_id
   returning * into r;

  return r;
end;
$$;

revoke all on function public.ai_record_provider_usage(uuid,bigint,bigint,bigint,bigint,numeric)
  from public,anon,authenticated;
grant execute on function public.ai_record_provider_usage(uuid,bigint,bigint,bigint,bigint,numeric)
  to service_role;

comment on function public.ai_record_provider_usage(uuid,bigint,bigint,bigint,bigint,numeric) is
'Records provider-observed usage on the canonical AI run before terminal settlement; service_role only and fail-closed after finalization.';
