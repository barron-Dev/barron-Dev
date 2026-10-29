-- Watchtower tenant-scoped camera registry and append-only probe evidence.
-- Source migration only: reconcile the existing live migration history before applying.
begin;

create table if not exists public.watchtower_cameras (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete restrict,
    site_id uuid null references public.physical_sites(id) on delete restrict,
    name text not null check (length(btrim(name)) between 1 and 200),
    endpoint text not null check (length(endpoint) between 1 and 2048),
    endpoint_host text not null check (length(endpoint_host) between 1 and 253),
    protocol text not null check (protocol in ('rtsp','rtsps')),
    enabled boolean not null default true,
    created_by text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, id)
);

create index if not exists watchtower_cameras_tenant_created_idx
    on public.watchtower_cameras (tenant_id, created_at desc);
alter table public.watchtower_cameras enable row level security;
revoke all on public.watchtower_cameras from anon, authenticated;
grant select, insert, update on public.watchtower_cameras to service_role;

create table if not exists public.watchtower_camera_probes (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete restrict,
    camera_id uuid not null,
    outcome text not null check (outcome in ('connected','failed','unavailable')),
    frame_sha256 text null check (frame_sha256 is null or frame_sha256 ~ '^[0-9a-f]{64}$'),
    frame_sequence bigint null check (frame_sequence is null or frame_sequence > 0),
    observed_at timestamptz not null default now(),
    duration_ms integer not null check (duration_ms >= 0),
    error_code text null check (error_code is null or length(error_code) <= 120),
    foreign key (tenant_id, camera_id) references public.watchtower_cameras(tenant_id, id) on delete restrict
);

create index if not exists watchtower_camera_probes_tenant_time_idx
    on public.watchtower_camera_probes (tenant_id, observed_at desc);
create index if not exists watchtower_camera_probes_camera_time_idx
    on public.watchtower_camera_probes (tenant_id, camera_id, observed_at desc);
alter table public.watchtower_camera_probes enable row level security;
revoke all on public.watchtower_camera_probes from anon, authenticated;
grant select, insert on public.watchtower_camera_probes to service_role;

create or replace function public.watchtower_reject_probe_mutation()
returns trigger language plpgsql set search_path = pg_catalog
as $$
begin
  raise exception 'watchtower_probe_evidence_append_only';
end;
$$;
revoke all on function public.watchtower_reject_probe_mutation() from public, anon, authenticated;
drop trigger if exists watchtower_camera_probes_append_only on public.watchtower_camera_probes;
create trigger watchtower_camera_probes_append_only
before update or delete on public.watchtower_camera_probes
for each row execute function public.watchtower_reject_probe_mutation();

commit;
