-- Align the live dark-web alias registry with the matcher runtime.
create table if not exists public.dw_watch_aliases (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    watchlist_id uuid not null references public.dw_watchlist(id) on delete cascade,
    kind text not null check (kind in ('domain','company_name','executive_name','email')),
    value text not null,
    alias_hash text not null,
    label text,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    unique (tenant_id, watchlist_id, kind, alias_hash)
);
create index if not exists dw_watch_aliases_lookup_idx on public.dw_watch_aliases(kind, alias_hash);
create index if not exists dw_watch_aliases_tenant_idx on public.dw_watch_aliases(tenant_id, watchlist_id);
alter table public.dw_watch_aliases enable row level security;
drop policy if exists dw_watch_aliases_select on public.dw_watch_aliases;
create policy dw_watch_aliases_select on public.dw_watch_aliases for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists dw_watch_aliases_insert on public.dw_watch_aliases;
create policy dw_watch_aliases_insert on public.dw_watch_aliases for insert with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists dw_watch_aliases_delete on public.dw_watch_aliases;
create policy dw_watch_aliases_delete on public.dw_watch_aliases for delete using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);