-- Native Cyclothone honeytokens: store token digests, never raw canary values.
create table if not exists public.dw_honeytokens (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null,
    label text not null check (length(btrim(label)) between 1 and 120),
    token_sha256 text not null check (token_sha256 ~ '^[0-9a-f]{64}$'),
    status text not null default 'active' check (status in ('active','revoked')),
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    last_hit_at timestamptz,
    unique (tenant_id, token_sha256)
);

create index if not exists dw_honeytokens_active_tenant_idx
    on public.dw_honeytokens (tenant_id, created_at desc)
    where status = 'active';

alter table public.dw_honeytokens enable row level security;
revoke all on public.dw_honeytokens from anon, authenticated;
grant select, insert, update on public.dw_honeytokens to service_role;

-- Service-only access is deliberate: raw tokens must be shown only during
-- authorized creation, while this table retains only the digest and metadata.
