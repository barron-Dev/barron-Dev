-- 151_ai_run_workload_usage.sql
-- Persist the workload layer already selected by the AI router on the canonical run.
-- The usage view is derived from ai_runs; this does not create a second ledger.

alter table public.ai_runs
  add column if not exists workload_layer text;

alter table public.ai_runs
  drop constraint if exists ai_runs_workload_layer_check;

alter table public.ai_runs
  add constraint ai_runs_workload_layer_check
  check (
    workload_layer is null
    or workload_layer in (
      'GENERAL','CUSTOMER_OPERATIONS','REASONING','SECURITY',
      'WEB_RESEARCH','THREAT_INTELLIGENCE','DARK_WEB','CRITICAL'
    )
  );

-- Keep the existing ai_start_run signature for older callers. The new overload
-- wraps it in the same transaction, then persists the validated workload label.
create or replace function public.ai_start_run(
  p_tenant_id uuid,
  p_agent_id uuid,
  p_agent_version integer,
  p_mission_id text,
  p_mission_version integer,
  p_mission_hash text,
  p_model_id text,
  p_model_version integer,
  p_provider_id text,
  p_provider_binding_version integer,
  p_idempotency_key text,
  p_request_fingerprint text,
  p_trace_id text,
  p_correlation_id text,
  p_workload_layer text
) returns public.ai_runs
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r public.ai_runs;
  v_workload_layer text := upper(trim(p_workload_layer));
begin
  if v_workload_layer is null or v_workload_layer not in (
    'GENERAL','CUSTOMER_OPERATIONS','REASONING','SECURITY',
    'WEB_RESEARCH','THREAT_INTELLIGENCE','DARK_WEB','CRITICAL'
  ) then
    raise exception 'invalid_workload_layer';
  end if;

  r := public.ai_start_run(
    p_tenant_id,p_agent_id,p_agent_version,p_mission_id,p_mission_version,
    p_mission_hash,p_model_id,p_model_version,p_provider_id,
    p_provider_binding_version,p_idempotency_key,p_request_fingerprint,
    p_trace_id,p_correlation_id
  );

  if r.workload_layer is not null and r.workload_layer <> v_workload_layer then
    raise exception 'idempotency_conflict';
  end if;

  update public.ai_runs
     set workload_layer = v_workload_layer
   where id = r.id and tenant_id = p_tenant_id
   returning * into r;

  return r;
end;
$$;

revoke all on function public.ai_start_run(
  uuid,uuid,integer,text,integer,text,text,integer,text,integer,text,text,text,text,text
) from public,anon,authenticated;
grant execute on function public.ai_start_run(
  uuid,uuid,integer,text,integer,text,text,integer,text,integer,text,text,text,text,text
) to service_role;

comment on column public.ai_runs.workload_layer is
'Explicit workload layer supplied by the canonical AI routing request; NULL means legacy/unattributed, never inferred.';

create or replace view public.ai_model_usage_by_workload
with (security_invoker = true)
as
select
  r.tenant_id,
  r.workload_layer,
  r.model_id,
  r.model_version,
  r.provider_id,
  count(*)::bigint as executions,
  count(*) filter (where r.run_state = 'COMPLETED')::bigint as completed_executions,
  count(*) filter (where r.run_state in ('FAILED','TIMEOUT','CANCELLED','REJECTED'))::bigint as failed_executions,
  coalesce(sum(r.tokens_in),0)::bigint as tokens_in,
  coalesce(sum(r.tokens_out),0)::bigint as tokens_out,
  coalesce(sum(r.tokens_cached),0)::bigint as tokens_cached,
  coalesce(sum(r.cost_usd),0)::numeric(18,8) as cost_usd,
  round(avg(r.latency_ms) filter (where r.latency_ms is not null),2) as avg_latency_ms,
  min(r.created_at) as first_execution_at,
  max(r.created_at) as last_execution_at
from public.ai_runs r
group by r.tenant_id,r.workload_layer,r.model_id,r.model_version,r.provider_id;

revoke all on public.ai_model_usage_by_workload from anon,authenticated;
grant select on public.ai_model_usage_by_workload to authenticated;

comment on view public.ai_model_usage_by_workload is
'Workload-layer token, cost, latency and execution aggregates derived from canonical ai_runs. NULL workload remains explicitly unattributed.';
