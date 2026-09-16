-- Brand Protection schema. Service-role collectors write findings through the RPC;
-- tenant-facing reads/writes remain tenant scoped.
create table if not exists brands (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
    name text not null, primary_domain text not null, domains text[] not null default '{}', keywords text[] not null default '{}',
    trademarks text[] not null default '{}', social_handles text[] not null default '{}', app_ids jsonb not null default '{}'::jsonb,
    logo_url text, monitor_ct_logs boolean not null default true, monitor_whois boolean not null default true,
    monitor_social boolean not null default true, monitor_apps boolean not null default true, monitor_market boolean not null default true,
    similarity_min real not null default 0.75 check (similarity_min >= 0.5 and similarity_min <= 0.99),
    enabled boolean not null default true, created_by uuid references auth.users(id) on delete set null, created_at timestamptz not null default now(),
    unique (tenant_id, primary_domain)
);
create index if not exists idx_brands_tenant_enabled on brands(tenant_id, enabled);
alter table brands enable row level security;
drop policy if exists brands_tenant_select on brands;
create policy brands_tenant_select on brands for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists brand_threats (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
    brand_id uuid not null references brands(id) on delete cascade,
    kind text not null check (kind in ('typosquat','homoglyph','combosquat','tld_swap','subdomain_trick','social_handle','fake_app','fake_listing','phishing_page','trademark_abuse','lookalike_logo','fake_recruitment','fake_support')),
    identifier text not null, url text, platform text, similarity real not null default 0 check (similarity >= 0 and similarity <= 1), distance int,
    registrar text, hosting_ip inet, hosting_asn text, country text, cert_issuer text, cert_first_seen timestamptz,
    logo_phash text, logo_match real, screenshot_ref text, page_hash text, metadata jsonb not null default '{}'::jsonb,
    severity text not null default 'medium' check (severity in ('low','medium','high','critical')),
    status text not null default 'active' check (status in ('active','monitoring','takedown_requested','taken_down','false_positive','resolved')),
    takedown_provider text, takedown_ref text, takedown_at timestamptz, resolved_at timestamptz,
    case_id uuid references crime_cases(id) on delete set null, first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
    unique (tenant_id, kind, identifier)
);
create index if not exists idx_brand_threats_tenant_seen on brand_threats(tenant_id, first_seen desc);
create index if not exists idx_brand_threats_brand_status on brand_threats(brand_id, status);
create index if not exists idx_brand_threats_active on brand_threats(tenant_id) where status = 'active';
alter table brand_threats enable row level security;
drop policy if exists brand_threats_tenant_select on brand_threats;
create policy brand_threats_tenant_select on brand_threats for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists ct_log_entries (
 id bigserial primary key, certificate_id text not null unique, common_name text, san_dns text[] not null default '{}', issuer text,
 not_before timestamptz, not_after timestamptz, log_source text, first_seen timestamptz not null default now()
);
create index if not exists idx_ct_san on ct_log_entries using gin(san_dns);
create table if not exists brand_permutations (
 id bigserial primary key, base text not null, permutation text not null, technique text not null, created_at timestamptz not null default now(), unique(base, permutation)
);
create index if not exists idx_perm_lookup on brand_permutations(permutation);
create table if not exists takedown_templates (
 id uuid primary key default gen_random_uuid(), tenant_id uuid references tenants(id) on delete cascade, provider text not null, category text not null,
 subject text not null, body text not null, endpoint_url text, email text, created_at timestamptz not null default now()
);
alter table takedown_templates enable row level security;
drop policy if exists takedown_templates_tenant_select on takedown_templates;
create policy takedown_templates_tenant_select on takedown_templates for select to authenticated using (tenant_id is null or tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create or replace function record_brand_threat(p_tenant uuid, p_brand uuid, p_kind text, p_identifier text, p_url text, p_platform text, p_similarity real, p_severity text, p_metadata jsonb)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_tenant uuid;
begin
  select tenant_id into v_tenant from brands where id = p_brand;
  if v_tenant is null or v_tenant <> p_tenant then raise exception 'brand tenant mismatch'; end if;
  if p_similarity < 0 or p_similarity > 1 then raise exception 'invalid similarity'; end if;
  insert into brand_threats(tenant_id,brand_id,kind,identifier,url,platform,similarity,severity,metadata)
  values(p_tenant,p_brand,p_kind,lower(trim(p_identifier)),p_url,p_platform,p_similarity,p_severity,coalesce(p_metadata,'{}'::jsonb))
  on conflict(tenant_id,kind,identifier) do update set last_seen=now(), similarity=greatest(brand_threats.similarity,excluded.similarity), severity=case
    when brand_threats.severity='critical' or excluded.severity='critical' then 'critical'
    when brand_threats.severity='high' or excluded.severity='high' then 'high'
    when brand_threats.severity='medium' or excluded.severity='medium' then 'medium' else 'low' end,
    metadata=brand_threats.metadata || excluded.metadata
  returning id into v_id;
  return v_id;
end $$;
revoke all on function record_brand_threat(uuid,uuid,text,text,text,text,real,text,jsonb) from public, anon, authenticated;
grant execute on function record_brand_threat(uuid,uuid,text,text,text,text,real,text,jsonb) to service_role;
