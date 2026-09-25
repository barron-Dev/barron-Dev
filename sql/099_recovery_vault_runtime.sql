-- Recovery Vault production foundation.
-- Immutable bytes remain in an externally configured WORM/Object-Lock COMPLIANCE bucket.

create table if not exists public.recovery_vault_policies (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    region text not null,
    bucket text not null,
    prefix text not null,
    retention_days int not null check (retention_days > 0),
    rpo_minutes int not null default 15 check (rpo_minutes between 1 and 1440),
    object_lock_mode text not null check (object_lock_mode = 'COMPLIANCE'),
    kms_key_ref text not null,
    enabled boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, region)
);
create table if not exists public.recovery_snapshots (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    region text not null,
    device_id uuid references public.devices(id) on delete set null,
    snapshot_type text not null check (snapshot_type in ('full','incremental')),
    parent_snapshot_id uuid references public.recovery_snapshots(id) on delete restrict,
    started_at timestamptz not null,
    completed_at timestamptz,
    status text not null default 'running' check (status in ('running','complete','failed','verified','restore_locked')),
    manifest_key text,
    manifest_sha256 text,
    object_count bigint not null default 0,
    byte_count bigint not null default 0,
    error_code text,
    created_at timestamptz not null default now()
);
create index if not exists idx_recovery_snapshots_tenant_time on public.recovery_snapshots(tenant_id, created_at desc);
create table if not exists public.recovery_objects (
    id uuid primary key default gen_random_uuid(),
    snapshot_id uuid not null references public.recovery_snapshots(id) on delete cascade,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    object_key text not null,
    version_id text not null,
    sha256 text not null,
    size_bytes bigint not null check (size_bytes >= 0),
    content_type text,
    encrypted boolean not null default true,
    kms_key_ref text not null,
    retention_until timestamptz not null,
    verified_at timestamptz,
    created_at timestamptz not null default now(),
    unique (snapshot_id, object_key, version_id)
);
create index if not exists idx_recovery_objects_tenant on public.recovery_objects(tenant_id, created_at desc);
create index if not exists idx_recovery_objects_hash on public.recovery_objects(sha256);
create table if not exists public.recovery_restore_jobs (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    snapshot_id uuid not null references public.recovery_snapshots(id) on delete restrict,
    target_device_id uuid references public.devices(id) on delete set null,
    clean_host_required boolean not null default true,
    status text not null default 'queued' check (status in ('queued','verifying','restoring','verified','failed','cancelled')),
    requested_by uuid references auth.users(id) on delete set null,
    verification_sha256 text,
    restored_object_count bigint not null default 0,
    restored_byte_count bigint not null default 0,
    error_code text,
    requested_at timestamptz not null default now(),
    completed_at timestamptz
);
create index if not exists idx_recovery_restore_tenant on public.recovery_restore_jobs(tenant_id, requested_at desc);
create table if not exists public.recovery_verifications (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    snapshot_id uuid not null references public.recovery_snapshots(id) on delete restrict,
    verification_type text not null check (verification_type in ('manifest','object','restore','rpo')),
    passed boolean not null,
    checked_count bigint not null default 0,
    failure_count bigint not null default 0,
    verifier_version text not null,
    details jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
create index if not exists idx_recovery_verifications_snapshot on public.recovery_verifications(snapshot_id, created_at desc);

alter table public.recovery_vault_policies enable row level security;
alter table public.recovery_snapshots enable row level security;
alter table public.recovery_objects enable row level security;
alter table public.recovery_restore_jobs enable row level security;
alter table public.recovery_verifications enable row level security;

drop policy if exists recovery_policy_tenant on public.recovery_vault_policies;
create policy recovery_policy_tenant on public.recovery_vault_policies for all to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid) with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists recovery_snapshots_tenant on public.recovery_snapshots;
create policy recovery_snapshots_tenant on public.recovery_snapshots for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists recovery_objects_tenant on public.recovery_objects;
create policy recovery_objects_tenant on public.recovery_objects for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists recovery_restore_tenant on public.recovery_restore_jobs;
create policy recovery_restore_tenant on public.recovery_restore_jobs for select, insert to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid) with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists recovery_verifications_tenant on public.recovery_verifications;
create policy recovery_verifications_tenant on public.recovery_verifications for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

grant select, insert, update on public.recovery_vault_policies to authenticated;
grant select on public.recovery_snapshots, public.recovery_objects, public.recovery_verifications to authenticated;
grant select, insert on public.recovery_restore_jobs to authenticated;