-- 102_ai_model_routing_usage.sql
-- Canonical model/provider routing preferences and usage analytics.
-- Routing never replaces execution authority: an execution binding must still
-- authorize the selected model/provider for the exact mission.

create table if not exists public.ai_model_routes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  workload_layer text not null
    check (workload_layer in (
      'GENERAL','CUSTOMER_OPERATIONS','REASONING','SECURITY',
      'WEB_RESEARCH','THREAT_INTELLIGENCE','DARK_WEB','CRITICAL'
    )),
  route_name text not null,
  model_id text not null,
  provider_id text not null,
  priority integer not null default 100 check (priority > 0),
  enabled boolean not null default true,
  max_risk_level text not null default 'LOW'
    check (max_risk_level in ('LOW','MEDIUM','HIGH','CRITICAL')),
  capabilities jsonb not null default '[]'::jsonb,
  constraints jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, workload_layer, route_name),
  check (jsonb_typeof(capabilities) = 'array'),
  check (jsonb_typeof(constraints) = 'object')
);

create index if not exists idx_ai_model_routes_lookup
  on public.ai_model_routes(tenant_id, workload_layer, enabled, priority);

alter table public.ai_model_routes enable row level security;
revoke all on public.ai_model_routes from public,anon,authenticated;

drop policy if exists ai_model_routes_member_read on public.ai_model_routes;
create policy ai_model_routes_member_read on public.ai_model_routes
for select to authenticated
using (
  tenant_id is null
  or exists (
    select 1 from public.tenant_members tm
     where tm.tenant_id = ai_model_routes.tenant_id
       and tm.user_id = auth.uid()
  )
);

grant select on public.ai_model_routes to authenticated;

create or replace function public.ai_resolve_model_route(
  p_tenant_id uuid,
  p_workload_layer text,
  p_risk_level text,
  p_required_capabilities jsonb default '[]'::jsonb,
  p_mission_id text default null,
  p_mission_version integer default null,
  p_mission_hash text default null
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r record;
  v_route jsonb;
begin
  if p_tenant_id is null
     or p_workload_layer is null
     or p_workload_layer not in (
       'GENERAL','CUSTOMER_OPERATIONS','REASONING','SECURITY',
       'WEB_RESEARCH','THREAT_INTELLIGENCE','DARK_WEB','CRITICAL'
     )
     or p_risk_level is null
     or p_risk_level not in ('LOW','MEDIUM','HIGH','CRITICAL')
     or jsonb_typeof(coalesce(p_required_capabilities,'[]'::jsonb)) <> 'array' then
    raise exception 'invalid_model_route_request';
  end if;

  /*
   * A route is only executable when an exact active execution binding exists.
   * This preserves the existing canonical execution identity boundary.
   */
  for r in
    select
      mr.id as route_id,
      mr.route_name,
      mr.model_id,
      m.version as model_version,
      mr.provider_id,
      mr.priority,
      mr.max_risk_level,
      mr.capabilities,
      mr.constraints,
      mr.tenant_id as route_tenant_id
    from public.ai_model_routes mr
    join public.ai_models m
      on m.id = mr.model_id
     and m.tenant_id = coalesce(mr.tenant_id, p_tenant_id)
     and m.lifecycle_state = 'ACTIVE'
    where mr.enabled
      and (mr.tenant_id = p_tenant_id or mr.tenant_id is null)
      and mr.workload_layer = p_workload_layer
      and case p_risk_level
        when 'LOW' then mr.max_risk_level in ('LOW','MEDIUM','HIGH','CRITICAL')
        when 'MEDIUM' then mr.max_risk_level in ('MEDIUM','HIGH','CRITICAL')
        when 'HIGH' then mr.max_risk_level in ('HIGH','CRITICAL')
        when 'CRITICAL' then mr.max_risk_level = 'CRITICAL'
      end
      and not exists (
        select 1
        from jsonb_array_elements_text(coalesce(p_required_capabilities,'[]'::jsonb)) req
        where not (mr.capabilities ? req)
      )
      and (
        p_mission_id is null
        or exists (
          select 1
          from public.ai_execution_bindings b
          where b.tenant_id = p_tenant_id
            and b.mission_id = p_mission_id
            and b.mission_version = p_mission_version
            and b.mission_hash = p_mission_hash
            and b.status = 'ACTIVE'
            and b.model_id = mr.model_id
            and b.model_version = m.version
            and b.provider_id = mr.provider_id
        )
      )
      and exists (
        select 1
        from public.ai_providers p
        where p.id = mr.provider_id
          and (p.tenant_id = p_tenant_id or p.tenant_id is null)
          and p.lifecycle_state = 'ACTIVE'
          and p.circuit_state <> 'OPEN'
      )
    order by
      case when mr.tenant_id = p_tenant_id then 0 else 1 end,
      mr.priority asc,
      mr.id
  loop
    v_route := jsonb_build_object(
      'route_id', r.route_id,
      'route_name', r.route_name,
      'workload_layer', p_workload_layer,
      'model_id', r.model_id,
      'model_version', r.model_version,
      'provider_id', r.provider_id,
      'priority', r.priority,
      'max_risk_level', r.max_risk_level,
      'capabilities', r.capabilities,
      'constraints', r.constraints,
      'tenant_specific', r.route_tenant_id is not null
    );
    return v_route;
  end loop;

  raise exception 'ai_model_route_not_available';
end;
$$;

revoke all on function public.ai_resolve_model_route(uuid,text,text,jsonb,text,integer,text)
  from public,anon,authenticated;
grant execute on function public.ai_resolve_model_route(uuid,text,text,jsonb,text,integer,text)
  to service_role;

comment on function public.ai_resolve_model_route(uuid,text,text,jsonb,text,integer,text) is
'Selects an approved model/provider route for a workload layer while requiring an exact active execution binding when mission identity is supplied. Routing is not execution authority.';

-- ---------------------------------------------------------------------------
-- Usage analytics: derived from canonical ai_runs. No duplicate usage ledger.
-- ---------------------------------------------------------------------------

create or replace view public.ai_model_usage_summary
with (security_invoker = true)
as
select
  r.tenant_id,
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
group by r.tenant_id, r.model_id, r.model_version, r.provider_id;

create or replace view public.ai_model_usage_by_mission
with (security_invoker = true)
as
select
  r.tenant_id,
  r.mission_id,
  r.mission_version,
  r.model_id,
  r.model_version,
  r.provider_id,
  count(*)::bigint as executions,
  coalesce(sum(r.tokens_in),0)::bigint as tokens_in,
  coalesce(sum(r.tokens_out),0)::bigint as tokens_out,
  coalesce(sum(r.cost_usd),0)::numeric(18,8) as cost_usd,
  round(avg(r.latency_ms) filter (where r.latency_ms is not null),2) as avg_latency_ms
from public.ai_runs r
group by
  r.tenant_id, r.mission_id, r.mission_version,
  r.model_id, r.model_version, r.provider_id;

create or replace view public.ai_model_usage_daily
with (security_invoker = true)
as
select
  date_trunc('day', r.created_at) as usage_day,
  r.tenant_id,
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
  round(avg(r.latency_ms) filter (where r.latency_ms is not null),2) as avg_latency_ms
from public.ai_runs r
group by
  date_trunc('day', r.created_at),
  r.tenant_id, r.model_id, r.model_version, r.provider_id;

revoke all on public.ai_model_usage_summary,
  public.ai_model_usage_by_mission,
  public.ai_model_usage_daily
from anon,authenticated;

grant select on public.ai_model_usage_summary,
  public.ai_model_usage_by_mission,
  public.ai_model_usage_daily
to authenticated;

comment on view public.ai_model_usage_summary is
'Derived model/provider utilization from canonical AI runs. Tenant-scoped; never a second source of execution truth.';

comment on view public.ai_model_usage_by_mission is
'Derived model/provider utilization by tenant and mission for workload-level analysis.';

comment on view public.ai_model_usage_daily is
'Daily derived model/provider usage for capacity, cost, and demand trend analysis.';
