-- Server-side agent identity and canonical endpoint event schema.
-- Existing devices are extended; no replacement device interface is introduced.

alter table devices
    add column if not exists mtls_cert_sha256 text;

alter table devices
    add column if not exists agent_enabled boolean not null default true;

create unique index if not exists idx_devices_mtls_cert_sha256
    on devices(mtls_cert_sha256)
    where mtls_cert_sha256 is not null;

create table if not exists endpoint_events (
    id              uuid primary key default gen_random_uuid(),
    tenant_id       uuid not null references tenants(id) on delete cascade,
    device_id       uuid not null references devices(id) on delete cascade,
    event_id        text not null,
    schema_version  integer not null,
    event_type      text not null,
    observed_at     timestamptz not null,
    payload         jsonb not null,
    created_at      timestamptz not null default now(),
    unique (device_id, event_id)
);

create index if not exists idx_endpoint_events_tenant_time
    on endpoint_events(tenant_id, observed_at desc);

create index if not exists idx_endpoint_events_device_time
    on endpoint_events(device_id, observed_at desc);

alter table endpoint_events enable row level security;

drop policy if exists endpoint_events_tenant_select on endpoint_events;
create policy endpoint_events_tenant_select on endpoint_events
    for select to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

grant select on endpoint_events to authenticated;
