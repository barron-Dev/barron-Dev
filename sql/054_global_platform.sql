-- sql/054_global_platform.sql
-- Global platform foundation. Preserves existing sql/051_fapi.sql.
-- Regions/catalog are data; runtime code never hardcodes a region list.

create table if not exists regions (
  code text primary key,
  name text not null,
  continent text not null,
  country text not null check (country ~ '^[A-Z]{2}$'),
  sovereignty_tier text not null default 'standard'
    check (sovereignty_tier in ('standard','gdpr','sovereign','govcloud')),
  api_base_url text not null,
  sandbox_base_url text not null,
  supabase_project text not null,
  storage_bucket text not null,
  kms_key_ref text not null,
  compliance jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists global_audit (
  id bigserial primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  region_code text not null references regions(code),
  actor text not null,
  action text not null,
  resource text not null,
  resource_id text,
  cross_border boolean not null default false,
  destination_region text references regions(code),
  legal_basis text,
  metadata jsonb not null default '{}'::jsonb,
  ip inet,
  ts timestamptz not null default now()
);
create index if not exists idx_global_audit_tenant_ts on global_audit(tenant_id, ts desc);
create index if not exists idx_global_audit_cross on global_audit(cross_border) where cross_border;

create table if not exists cross_region_metrics (
  source_region text not null references regions(code),
  tenant_id uuid not null references tenants(id) on delete cascade,
  metric_date date not null,
  detection_count int not null default 0 check (detection_count >= 0),
  blocked_count int not null default 0 check (blocked_count >= 0),
  case_count int not null default 0 check (case_count >= 0),
  device_count int not null default 0 check (device_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (source_region, tenant_id, metric_date)
);

alter table regions enable row level security;
alter table global_audit enable row level security;
alter table cross_region_metrics enable row level security;

drop policy if exists global_audit_tenant on global_audit;
create policy global_audit_tenant on global_audit for select to authenticated
using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists cross_region_metrics_tenant on cross_region_metrics;
create policy cross_region_metrics_tenant on cross_region_metrics for select to authenticated
using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

-- No client role gets direct writes to the audit/metrics tables.
revoke all on global_audit, cross_region_metrics from anon, authenticated;

create or replace function write_global_audit(
  p_tenant uuid, p_action text, p_resource text, p_resource_id text,
  p_actor text, p_cross_border boolean default false,
  p_dest_region text default null, p_legal_basis text default null,
  p_metadata jsonb default '{}'::jsonb
) returns void
language plpgsql security definer set search_path=public
as $$
begin
  if not exists (select 1 from tenants where id = p_tenant) then
    raise exception 'tenant not found';
  end if;
  insert into global_audit(
    tenant_id, region_code, actor, action, resource, resource_id,
    cross_border, destination_region, legal_basis, metadata
  ) values (
    p_tenant,
    current_setting('app.region', true),
    p_actor, p_action, p_resource, p_resource_id,
    p_cross_border, p_dest_region, p_legal_basis, coalesce(p_metadata,'{}'::jsonb)
  );
end $$;

revoke all on function write_global_audit(uuid,text,text,text,text,boolean,text,text,jsonb) from public, anon, authenticated;
grant execute on function write_global_audit(uuid,text,text,text,text,boolean,text,text,jsonb) to service_role;

create or replace function global_stats(p_tenant uuid, p_hours int default 24)
returns jsonb language sql stable security definer set search_path=public
as $$
  select jsonb_build_object(
    'detections',(select count(*) from detections where tenant_id=p_tenant and created_at > now()-(greatest(p_hours,1)||' hours')::interval),
    'blocked',(select count(*) from detections where tenant_id=p_tenant and verdict='block' and created_at > now()-(greatest(p_hours,1)||' hours')::interval),
    'cases',(select count(*) from crime_cases where tenant_id=p_tenant and created_at > now()-(greatest(p_hours,1)||' hours')::interval),
    'devices',(select count(*) from devices where tenant_id=p_tenant and status='active'),
    'alerts',(select count(*) from dw_alerts where tenant_id=p_tenant and status='new'),
    'catalog_peers',(select count(*) from federation_subscriptions where tenant_id=p_tenant and receive_enabled=true)
  );
$$;
revoke all on function global_stats(uuid,int) from public, anon, authenticated;
grant execute on function global_stats(uuid,int) to service_role;
