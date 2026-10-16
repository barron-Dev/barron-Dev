-- Cyclothone Dark Web public-source registry base schema.
-- Reconciled against production schema on 2026-10-12.
-- This migration was already recorded in the production database under
-- 20261012083522_darkweb_source_registry_base; this file restores repository
-- source-of-truth and must not be manually re-applied to production.

create table if not exists public.source_registry (
    id uuid primary key default gen_random_uuid(),
    identity text not null unique,
    source_type text not null check (source_type in (
        'telegram','social','forum','paste','tor','i2p','irc','discord',
        'code','breach_feed','ransomware','other'
    )),
    display_name text not null,
    discovered_by text not null check (discovered_by in (
        'seed','snowball','keyword','forward','successor','link','manual'
    )),
    parent_identity text,
    discovery_timestamp timestamptz not null default now(),
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    last_checked timestamptz,
    monitoring_status text not null default 'QUARANTINED'
        check (monitoring_status in ('ACTIVE','QUARANTINED','EXPIRED','EXCLUDED')),
    channel_status text check (
        channel_status is null or channel_status in ('VALID','EXPIRED','OFFLINE','ONLINE','PRIVATE')
    ),
    validation_status text check (
        validation_status is null or validation_status in ('HIGH','MEDIUM','LOW','SCAM')
    ),
    validation_score integer check (validation_score is null or validation_score between 0 and 10),
    message_count bigint not null default 0,
    ioc_yield integer not null default 0,
    mirror_count integer not null default 0,
    language varchar,
    topic_tags text[] not null default '{}',
    source_url text,
    successor_of uuid references public.source_registry(id),
    successor_candidates uuid[] not null default '{}',
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists source_registry_identity_lower_uidx
    on public.source_registry (lower(identity));
create index if not exists source_registry_active_pick_idx
    on public.source_registry (source_type, last_checked nulls first, first_seen)
    where monitoring_status = 'ACTIVE';
create index if not exists source_registry_channel_status_idx
    on public.source_registry (channel_status, monitoring_status);
create index if not exists source_registry_parent_idx
    on public.source_registry (parent_identity);
create index if not exists source_registry_quarantine_idx
    on public.source_registry (first_seen)
    where monitoring_status = 'QUARANTINED';

alter table public.source_registry enable row level security;
revoke all on public.source_registry from anon, authenticated;
grant all on public.source_registry to service_role;
