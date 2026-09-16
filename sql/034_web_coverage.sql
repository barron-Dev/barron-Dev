-- Sentinel 3-web coverage: customer-authorized surface/deep targets plus dark-web
-- targets. This layer stores provenance and indicators, never recovered passwords.

create table if not exists public.web_crawl_targets (
    id uuid primary key default gen_random_uuid(), tenant_id uuid references public.tenants(id) on delete cascade,
    layer text not null check (layer in ('surface','deep','dark')),
    kind text not null check (kind in ('domain','paste_site','forum','marketplace','onion_service','search_engine','api','rss')),
    url text not null, auth_ref text,
    crawl_interval integer not null default 3600 check (crawl_interval between 60 and 604800),
    max_depth integer not null default 1 check (max_depth between 0 and 3),
    respect_robots boolean not null default true, enabled boolean not null default true,
    last_crawl_at timestamptz, last_status text, created_at timestamptz not null default now()
);
create index if not exists web_crawl_targets_layer_idx on public.web_crawl_targets(layer, enabled);
create index if not exists web_crawl_targets_tenant_idx on public.web_crawl_targets(tenant_id, enabled);
alter table public.web_crawl_targets enable row level security;
drop policy if exists web_crawl_targets_select on public.web_crawl_targets;
create policy web_crawl_targets_select on public.web_crawl_targets for select using (tenant_id is null or tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists web_crawl_targets_insert on public.web_crawl_targets;
create policy web_crawl_targets_insert on public.web_crawl_targets for insert with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists web_crawl_targets_update on public.web_crawl_targets;
create policy web_crawl_targets_update on public.web_crawl_targets for update using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid) with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

create table if not exists public.web_crawl_pages (
    id bigint generated always as identity primary key, target_id uuid not null references public.web_crawl_targets(id) on delete cascade,
    url text not null, content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'), status_code integer, content_type text,
    matched_terms text[] not null default '{}', emails_found text[] not null default '{}', urls_found text[] not null default '{}', wallets_found text[] not null default '{}',
    credentials_found integer not null default 0 check (credentials_found >= 0), snapshot_ref text,
    severity text not null default 'medium' check (severity in ('medium','high','critical')),
    tenant_id uuid references public.tenants(id) on delete cascade, first_seen timestamptz not null default now(), unique (target_id, content_hash)
);
create index if not exists web_crawl_pages_tenant_idx on public.web_crawl_pages(tenant_id, first_seen desc) where tenant_id is not null;
create index if not exists web_crawl_pages_target_idx on public.web_crawl_pages(target_id, first_seen desc);
alter table public.web_crawl_pages enable row level security;
drop policy if exists web_crawl_pages_tenant on public.web_crawl_pages;
create policy web_crawl_pages_tenant on public.web_crawl_pages for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

create table if not exists public.search_dorks (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete cascade,
    engine text not null check (engine in ('google','bing','duckduckgo','yandex')), query text not null check (length(trim(query)) between 1 and 500),
    category text not null check (length(trim(category)) between 1 and 64), enabled boolean not null default true, last_run_at timestamptz, created_at timestamptz not null default now()
);
create index if not exists search_dorks_tenant_idx on public.search_dorks(tenant_id, enabled);
alter table public.search_dorks enable row level security;
drop policy if exists search_dorks_tenant on public.search_dorks;
create policy search_dorks_tenant on public.search_dorks for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create policy search_dorks_insert on public.search_dorks for insert with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create policy search_dorks_update on public.search_dorks for update using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid) with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create policy search_dorks_delete on public.search_dorks for delete using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

insert into public.dw_sources(id,name,kind,endpoint,poll_interval_seconds) values
('web_surface','Sentinel surface web crawler','custom',null,900),
('web_deep','Sentinel deep web authorized sources','custom',null,21600),
('web_dark','Sentinel dark web authorized crawler','custom',null,900)
on conflict(id) do nothing;

-- No fabricated .onion endpoints or provider credentials are seeded. Existing 032
-- global sources remain authoritative for HIBP/Telegram/Pastebin/GitHub/Ransomwatch.
revoke all on table public.web_crawl_targets from anon, authenticated;
revoke all on table public.web_crawl_pages from anon, authenticated;
revoke all on table public.search_dorks from anon, authenticated;
grant select on public.web_crawl_targets to authenticated;
grant select on public.web_crawl_pages to authenticated;
grant select, insert, update, delete on public.search_dorks to authenticated;
