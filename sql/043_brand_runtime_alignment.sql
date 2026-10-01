-- Align brand monitoring tables and persistence RPC with the live schedulers.
create table if not exists public.brands (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    name text not null,
    primary_domain text not null,
    domains text[] not null default '{}',
    keywords text[] not null default '{}',
    social_handles text[] not null default '{}',
    app_ids jsonb not null default '{}'::jsonb,
    similarity_min numeric not null default 0.75 check (similarity_min between 0 and 1),
    monitor_ct_logs boolean not null default true,
    enabled boolean not null default true,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id,primary_domain)
);
create table if not exists public.brand_threats (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    brand_id uuid not null references public.brands(id) on delete cascade,
    kind text not null,
    identifier text not null,
    url text,
    platform text,
    similarity numeric,
    severity text not null default 'medium',
    metadata jsonb not null default '{}'::jsonb,
    first_seen_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    status text not null default 'open',
    unique (tenant_id,brand_id,kind,identifier)
);
create index if not exists brands_tenant_enabled_idx on public.brands(tenant_id,enabled);
create index if not exists brand_threats_tenant_status_idx on public.brand_threats(tenant_id,status,last_seen_at desc);
alter table public.brands enable row level security;
alter table public.brand_threats enable row level security;
drop policy if exists brands_select on public.brands;
create policy brands_select on public.brands for select to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists brands_insert on public.brands;
create policy brands_insert on public.brands for insert to authenticated with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists brands_update on public.brands;
create policy brands_update on public.brands for update to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid) with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists brands_delete on public.brands;
create policy brands_delete on public.brands for delete to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
drop policy if exists brand_threats_select on public.brand_threats;
create policy brand_threats_select on public.brand_threats for select to authenticated using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create or replace function public.record_brand_threat(p_tenant uuid,p_brand uuid,p_kind text,p_identifier text,p_url text,p_platform text,p_similarity numeric,p_severity text,p_metadata jsonb)
returns uuid language plpgsql security invoker set search_path=public as $$
declare v_id uuid;
begin
 insert into public.brand_threats(tenant_id,brand_id,kind,identifier,url,platform,similarity,severity,metadata)
 values(p_tenant,p_brand,p_kind,p_identifier,p_url,p_platform,p_similarity,p_severity,coalesce(p_metadata,'{}'::jsonb))
 on conflict (tenant_id,brand_id,kind,identifier)
 do update set url=excluded.url,platform=excluded.platform,similarity=excluded.similarity,severity=excluded.severity,metadata=excluded.metadata,last_seen_at=now(),status='open'
 returning id into v_id;
 return v_id;
end $$;
revoke all on function public.record_brand_threat(uuid,uuid,text,text,text,text,numeric,text,jsonb) from public;
grant execute on function public.record_brand_threat(uuid,uuid,text,text,text,text,numeric,text,jsonb) to authenticated;