-- Agent-side model distribution audit trail.
-- The models bucket remains private; model bytes are served only through the
-- authenticated device endpoint.

create table agent_model_sync (
    device_id       uuid not null references devices(id) on delete cascade,
    model_version   int not null,
    model_id        uuid not null references models(id) on delete cascade,
    artifact_sha256 text not null,
    downloaded_at   timestamptz not null default now(),
    primary key (device_id, model_version)
);

create index idx_agent_sync_device
    on agent_model_sync(device_id, downloaded_at desc);

alter table agent_model_sync enable row level security;

create policy agent_sync_tenant_select
    on agent_model_sync
    for select
    to authenticated
    using (
        device_id in (
            select d.id
            from devices d
            where d.tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid)
        )
    );

create policy agent_sync_tenant_insert
    on agent_model_sync
    for insert
    to authenticated
    with check (
        device_id in (
            select d.id
            from devices d
            where d.tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid)
        )
    );

-- New public-schema tables may require explicit Data API grants on current
-- Supabase projects. Service-role agent distribution jobs bypass RLS.
grant select on agent_model_sync to authenticated;
