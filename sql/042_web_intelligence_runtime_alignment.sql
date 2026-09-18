-- Align the live web-intelligence crawler registry with the application runtime.
create table if not exists public.web_crawl_targets (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    url text not null check (length(url) between 1 and 2048),
    layer text not null check (layer in ('surface','deep','dark')),
    enabled boolean not null default true,
    respect_robots boolean not null default true,
    max_depth integer not null default 0 check (max_depth between 0 and 10),
    crawl_interval integer not null default 3600 check (crawl_interval between 60 and 604800),
    last_crawl_at timestamptz,
    last_status text,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id,url)
);
create table if not exists public.web_crawl_pages (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    target_id uuid not null references public.web_crawl_targets(id) on delete cascade,
    url text not null,
    content_hash text not null,
    status_code integer,
    content_type text,
    matched_terms text[] not null default '{}',
    emails_found text[] not null default '{}',
    urls_found text[] not null default '{}',
    wallets_found text[] not null default '{}',
    credentials_found boolean not null default false,
    severity text not null default 'low',
    created_at timestamptz not null default now(),
    unique (target_id,content_hash)
);
create index if not exists web_crawl_targets_due_idx on public.web_crawl_targets(enabled,last_crawl_at);
create index if not exists web_crawl_targets_tenant_idx on public.web_crawl_targets(tenant_id);
create index if not exists web_crawl_pages_target_idx on public.web_crawl_pages(target_id,created_at desc);
create index if not exists web_crawl_pages_tenant_idx on public.web_crawl_pages(tenant_id,created_at desc);
alter table public.web_crawl_targets enable row level security;
alter table public.web_crawl_pages enable row level security;
drop policy if exists web_crawl_targets_select on public.web_crawl_targets;
create policy web_crawl_targets_select on public.web_crawl_targets for select to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists web_crawl_targets_insert on public.web_crawl_targets;
create policy web_crawl_targets_insert on public.web_crawl_targets for insert to authenticated with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists web_crawl_targets_update on public.web_crawl_targets;
create policy web_crawl_targets_update on public.web_crawl_targets for update to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid) with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists web_crawl_targets_delete on public.web_crawl_targets;
create policy web_crawl_targets_delete on public.web_crawl_targets for delete to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists web_crawl_pages_select on public.web_crawl_pages;
create policy web_crawl_pages_select on public.web_crawl_pages for select to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);