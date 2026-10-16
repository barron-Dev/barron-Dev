-- Cyclothone Dark Web source graph and append-only event trail.
-- Reconciled against production schema on 2026-10-12.
-- This migration was already recorded in production as
-- 20261012083534_darkweb_source_registry_supporting_tables; do not re-apply manually.

create table if not exists public.source_registry_edges (
    id uuid primary key default gen_random_uuid(),
    source_id uuid not null references public.source_registry(id) on delete cascade,
    target_id uuid not null references public.source_registry(id) on delete cascade,
    edge_type text not null check (edge_type in (
        'link','mention','forward','mirror','successor','external_reference'
    )),
    discovered_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    check (source_id <> target_id),
    unique (source_id, target_id, edge_type)
);
create index if not exists source_registry_edges_target_idx
    on public.source_registry_edges (target_id, edge_type);

create table if not exists public.source_registry_events (
    id bigint generated always as identity primary key,
    source_id uuid references public.source_registry(id) on delete set null,
    identity text not null,
    event_type text not null,
    event_at timestamptz not null default now(),
    details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object')
);
create index if not exists source_registry_events_identity_idx
    on public.source_registry_events (identity, event_at desc);

alter table public.source_registry_edges enable row level security;
alter table public.source_registry_events enable row level security;
revoke all on public.source_registry_edges, public.source_registry_events from anon, authenticated;
grant all on public.source_registry_edges, public.source_registry_events to service_role;
