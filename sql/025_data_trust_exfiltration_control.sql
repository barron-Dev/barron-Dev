-- Sentinel Data Trust / Data Exfiltration Control, migration 025.
-- Policy and provenance controls for authorized tenant-owned data and endpoints.
-- This migration records transfer decisions; endpoint enforcement remains platform-specific.

create table if not exists data_trust_policies (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text not null check (length(name) between 1 and 200),
    classification text not null check (classification in ('public','internal','confidential','restricted','regulated')),
    allowed_destinations text[] not null default '{}',
    allowed_device_trust text[] not null default '{managed,compliant}',
    allow_removable_media boolean not null default false,
    allow_bluetooth boolean not null default false,
    allow_cloud_upload boolean not null default false,
    encryption_required boolean not null default true,
    enabled boolean not null default true,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists data_trust_assets (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    policy_id uuid references data_trust_policies(id) on delete set null,
    object_ref text not null check (length(object_ref) between 1 and 1000),
    sha256 text check (sha256 is null or sha256 ~ '^[0-9a-fA-F]{64}$'),
    classification text not null check (classification in ('public','internal','confidential','restricted','regulated')),
    encryption_state text not null default 'encrypted' check (encryption_state in ('encrypted','plaintext','unknown')),
    provenance jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, object_ref)
);

create table if not exists data_trust_transfer_events (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    asset_id uuid references data_trust_assets(id) on delete set null,
    device_id uuid,
    actor_id uuid references auth.users(id) on delete set null,
    source_type text not null check (source_type in ('endpoint','browser','cloud','mobile','server','unknown')),
    destination_type text not null check (destination_type in ('endpoint','usb','bluetooth','cloud','browser','network','email','messaging','unknown')),
    destination_ref text,
    destination_trust text not null default 'unknown' check (destination_trust in ('managed','compliant','trusted','unknown','blocked')),
    bytes_transferred bigint not null default 0 check (bytes_transferred >= 0),
    content_inspected boolean not null default false,
    content_hash text check (content_hash is null or content_hash ~ '^[0-9a-fA-F]{64}$'),
    decision text not null check (decision in ('allow','block','quarantine','review')),
    reason_codes text[] not null default '{}',
    observed_at timestamptz not null,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists data_trust_transfer_tenant_time_idx on data_trust_transfer_events (tenant_id, observed_at desc);
create index if not exists data_trust_transfer_asset_idx on data_trust_transfer_events (asset_id, observed_at desc);
create index if not exists data_trust_asset_tenant_class_idx on data_trust_assets (tenant_id, classification);

alter table data_trust_policies enable row level security;
alter table data_trust_assets enable row level security;
alter table data_trust_transfer_events enable row level security;

drop policy if exists data_trust_policies_tenant_select on data_trust_policies;
create policy data_trust_policies_tenant_select on data_trust_policies for select to authenticated using (tenant_id = (select auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists data_trust_assets_tenant_select on data_trust_assets;
create policy data_trust_assets_tenant_select on data_trust_assets for select to authenticated using (tenant_id = (select auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists data_trust_transfer_tenant_select on data_trust_transfer_events;
create policy data_trust_transfer_tenant_select on data_trust_transfer_events for select to authenticated using (tenant_id = (select auth.jwt() ->> 'tenant_id')::uuid);

revoke all on data_trust_policies from anon, authenticated;
revoke all on data_trust_assets from anon, authenticated;
revoke all on data_trust_transfer_events from anon, authenticated;
grant select on data_trust_policies, data_trust_assets, data_trust_transfer_events to authenticated;
