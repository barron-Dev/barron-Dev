-- Sentinel Dark Web / External Exposure: explicit surface/deep/dark classification
-- and tenant-approved aliases for ransomware/company correlation.
-- This migration adds metadata only; collection remains limited to configured,
-- authorized sources and public material unless a customer connector is added.

alter table public.dw_sources
    add column if not exists exposure_layer text not null default 'surface'
        check (exposure_layer in ('surface','deep','dark')),
    add column if not exists access_mode text not null default 'public'
        check (access_mode in ('public','customer_authorized','licensed'));

update public.dw_sources
set exposure_layer = case id
        when 'ransomwatch' then 'dark'
        when 'hibp' then 'deep'
        else 'surface'
    end,
    access_mode = case id
        when 'hibp' then 'licensed'
        else 'public'
    end
where id in ('hibp','ransomwatch','pastebin_public','telegram_public','github_code');

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

create index if not exists dw_watch_aliases_lookup_idx
    on public.dw_watch_aliases(kind, alias_hash);
create index if not exists dw_watch_aliases_tenant_idx
    on public.dw_watch_aliases(tenant_id, watchlist_id);

alter table public.dw_watch_aliases enable row level security;

drop policy if exists dw_watch_aliases_select on public.dw_watch_aliases;
create policy dw_watch_aliases_select on public.dw_watch_aliases
    for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

drop policy if exists dw_watch_aliases_insert on public.dw_watch_aliases;
create policy dw_watch_aliases_insert on public.dw_watch_aliases
    for insert with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

drop policy if exists dw_watch_aliases_delete on public.dw_watch_aliases;
create policy dw_watch_aliases_delete on public.dw_watch_aliases
    for delete using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

-- Aliases are customer-approved correlation inputs. They never authorize a
-- collector to access a private source.
