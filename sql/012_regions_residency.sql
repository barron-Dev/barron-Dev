-- Regional data-plane residency model.
-- This migration is additive: it extends the existing tenants table and does not
-- replace the existing event/device/model interfaces.

create table if not exists regions (
    code                text primary key,
    name                text not null,
    continent           text not null check (continent in (
        'africa','asia','europe','north_america','south_america','oceania','middle_east'
    )),
    country             text not null check (country ~ '^[A-Z]{2}$'),
    sovereignty_tier    text not null default 'standard'
                        check (sovereignty_tier in ('standard','gdpr','sovereign','govcloud')),
    api_base_url        text not null check (api_base_url ~ '^https://'),
    sandbox_base_url    text not null check (sandbox_base_url ~ '^https://'),
    supabase_project    text not null,
    storage_bucket      text not null,
    kms_key_ref         text not null,
    compliance          jsonb not null default '{}'::jsonb,
    active              boolean not null default true,
    created_at          timestamptz not null default now()
);

insert into regions
    (code, name, continent, country, sovereignty_tier, api_base_url,
     sandbox_base_url, supabase_project, storage_bucket, kms_key_ref, compliance)
values
('ae-1','UAE Dubai','middle_east','AE','sovereign','https://api.ae-1.sentinel.security','https://sandbox.ae-1.sentinel.security','sentinel-ae','models-ae','vault://ae-1/signing','{"uae_pdpl":true,"soc2":true,"iso27001":true}'),
('za-1','South Africa Cape Town','africa','ZA','sovereign','https://api.za-1.sentinel.security','https://sandbox.za-1.sentinel.security','sentinel-za','models-za','vault://za-1/signing','{"popia":true,"soc2":true,"iso27001":true}'),
('ke-1','Kenya Nairobi','africa','KE','sovereign','https://api.ke-1.sentinel.security','https://sandbox.ke-1.sentinel.security','sentinel-ke','models-ke','vault://ke-1/signing','{"dpa_ke":true,"soc2":true}'),
('ng-1','Nigeria Lagos','africa','NG','sovereign','https://api.ng-1.sentinel.security','https://sandbox.ng-1.sentinel.security','sentinel-ng','models-ng','vault://ng-1/signing','{"ndpa_ng":true,"soc2":true}'),
('sg-1','Singapore','asia','SG','sovereign','https://api.sg-1.sentinel.security','https://sandbox.sg-1.sentinel.security','sentinel-sg','models-sg','vault://sg-1/signing','{"pdpa_sg":true,"soc2":true,"iso27001":true}'),
('in-1','India Mumbai','asia','IN','sovereign','https://api.in-1.sentinel.security','https://sandbox.in-1.sentinel.security','sentinel-in','models-in','vault://in-1/signing','{"dpdp_in":true,"soc2":true,"iso27001":true}'),
('jp-1','Japan Tokyo','asia','JP','sovereign','https://api.jp-1.sentinel.security','https://sandbox.jp-1.sentinel.security','sentinel-jp','models-jp','vault://jp-1/signing','{"appi_jp":true,"soc2":true,"iso27001":true}'),
('de-1','Germany Frankfurt','europe','DE','gdpr','https://api.de-1.sentinel.security','https://sandbox.de-1.sentinel.security','sentinel-de','models-de','vault://de-1/signing','{"gdpr":true,"soc2":true,"iso27001":true}'),
('uk-1','United Kingdom London','europe','GB','gdpr','https://api.uk-1.sentinel.security','https://sandbox.uk-1.sentinel.security','sentinel-uk','models-uk','vault://uk-1/signing','{"uk_gdpr":true,"soc2":true,"iso27001":true}'),
('us-1','United States','north_america','US','standard','https://api.us-1.sentinel.security','https://sandbox.us-1.sentinel.security','sentinel-us','models-us','vault://us-1/signing','{"soc2":true,"hipaa":true,"fedramp":false}')
on conflict (code) do update set
    name = excluded.name,
    continent = excluded.continent,
    country = excluded.country,
    sovereignty_tier = excluded.sovereignty_tier,
    api_base_url = excluded.api_base_url,
    sandbox_base_url = excluded.sandbox_base_url,
    supabase_project = excluded.supabase_project,
    storage_bucket = excluded.storage_bucket,
    kms_key_ref = excluded.kms_key_ref,
    compliance = excluded.compliance,
    active = true;

-- Existing tenants are assigned explicitly during migration. New tenant
-- provisioning must supply a region; there is deliberately no application
-- default that could silently move a new tenant across borders.
alter table tenants
    add column if not exists home_region text references regions(code),
    add column if not exists data_residency_policy text not null default 'strict'
        check (data_residency_policy in ('strict','regional_failover','global')),
    add column if not exists contract_type text not null default 'standard'
        check (contract_type in ('standard','enterprise','government','military')),
    add column if not exists government_agency text,
    add column if not exists security_clearance_level text,
    add column if not exists billing_entity text,
    add column if not exists tax_id text;

-- Backfill only legacy tenants that predate regional pinning. Operators should
-- review this assignment before enabling production residency enforcement.
update tenants set home_region = 'ae-1' where home_region is null;

alter table tenants alter column home_region set not null;

create index if not exists idx_tenants_region on tenants(home_region);
create index if not exists idx_tenants_contract_region on tenants(contract_type, home_region);

create table if not exists residency_audit (
    id                  bigint generated always as identity primary key,
    tenant_id           uuid not null,
    region_code         text not null references regions(code),
    actor               text not null,
    operation           text not null check (operation in ('write','read','export','delete','replicate')),
    resource            text not null,
    resource_id         text,
    cross_border        boolean not null default false,
    destination_region  text references regions(code),
    legal_basis         text check (legal_basis is null or legal_basis in ('contract','consent','legal_obligation','vital_interests')),
    ts                  timestamptz not null default now()
);

create index if not exists idx_residency_audit_tenant_ts on residency_audit(tenant_id, ts desc);
create index if not exists idx_residency_audit_cross_border on residency_audit(cross_border) where cross_border = true;

create or replace function prevent_residency_audit_mutation()
returns trigger language plpgsql as $$
begin
    raise exception 'residency_audit is append-only';
end;
$$;

drop trigger if exists residency_audit_immutable on residency_audit;
create trigger residency_audit_immutable
before update or delete on residency_audit
for each row execute function prevent_residency_audit_mutation();

alter table residency_audit enable row level security;
drop policy if exists residency_audit_service_insert on residency_audit;
create policy residency_audit_service_insert on residency_audit
    for insert to service_role with check (true);
drop policy if exists residency_audit_tenant_select on residency_audit;
create policy residency_audit_tenant_select on residency_audit
    for select to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
grant select on residency_audit to authenticated;

-- This table contains only aggregate metadata. It belongs in the control plane
-- and must never be populated with event content, evidence, reasons, PII, or
-- device identifiers.
create table if not exists cross_region_metrics (
    id                bigint generated always as identity primary key,
    source_region     text not null references regions(code),
    tenant_id         uuid not null,
    metric_date       date not null,
    detection_count   integer not null default 0 check (detection_count >= 0),
    blocked_count     integer not null default 0 check (blocked_count >= 0),
    case_count        integer not null default 0 check (case_count >= 0),
    device_count      integer not null default 0 check (device_count >= 0),
    updated_at        timestamptz not null default now(),
    unique (source_region, tenant_id, metric_date)
);

create index if not exists idx_cross_region_metrics_tenant
    on cross_region_metrics(tenant_id, metric_date desc);

comment on table cross_region_metrics is
    'Control-plane aggregate metadata only; never store raw events, detections, evidence, reasons, device IDs, or PII here.';
