-- Cyclothone source-registry least-privilege correction.
-- Production read-only inspection on 2026-10-12 found table-level grants for
-- authenticated despite RLS being enabled and no policies being present.
-- This migration is for a future reviewed deployment; it has NOT been applied.
begin;

revoke all privileges on table
    public.source_registry,
    public.source_registry_edges,
    public.source_registry_events
from public, anon, authenticated;

grant select, insert, update, delete, truncate, references, trigger
on table
    public.source_registry,
    public.source_registry_edges,
    public.source_registry_events
to service_role;

alter table public.source_registry enable row level security;
alter table public.source_registry_edges enable row level security;
alter table public.source_registry_events enable row level security;

comment on table public.source_registry is
    'Internal service-role-only registry of public defensive threat-intelligence sources.';
comment on table public.source_registry_edges is
    'Internal service-role-only relationship graph for public defensive source discovery.';
comment on table public.source_registry_events is
    'Internal service-role-only event trail for public defensive source checks.';

commit;
