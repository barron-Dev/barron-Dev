-- 040_regions_runtime_alignment.sql
-- Align the repository migration contract with the production region router.
-- Safe to re-run against environments where the runtime region registry already exists.

create table if not exists public.regions (
  code text primary key,
  name text not null,
  continent text,
  country text,
  sovereignty_tier text not null default 'standard',
  api_base_url text not null,
  sandbox_base_url text not null,
  supabase_project text,
  storage_bucket text,
  kms_key_ref text,
  compliance jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.regions
  add column if not exists continent text,
  add column if not exists country text,
  add column if not exists supabase_project text,
  add column if not exists storage_bucket text,
  add column if not exists kms_key_ref text,
  add column if not exists updated_at timestamptz not null default now();

insert into public.regions
  (code,name,continent,country,sovereignty_tier,api_base_url,sandbox_base_url,
   supabase_project,storage_bucket,kms_key_ref,compliance,active)
values
  ('ae-1','UAE Dubai','middle_east','AE','sovereign',
   'https://cyclothone.online','https://cyclothone.online',
   'whcomikcftbousoqzeal','models-ae','vault://ae-1/signing',
   '{"uae_pdpl":true,"soc2":true,"iso27001":true}'::jsonb,true)
on conflict (code) do update set
  name=excluded.name,
  continent=excluded.continent,
  country=excluded.country,
  sovereignty_tier=excluded.sovereignty_tier,
  api_base_url=excluded.api_base_url,
  sandbox_base_url=excluded.sandbox_base_url,
  supabase_project=excluded.supabase_project,
  storage_bucket=excluded.storage_bucket,
  kms_key_ref=excluded.kms_key_ref,
  compliance=excluded.compliance,
  active=true,
  updated_at=now();

alter table public.tenants
  add column if not exists home_region text,
  add column if not exists data_residency_policy text not null default 'strict',
  add column if not exists contract_type text not null default 'standard',
  add column if not exists government_agency text,
  add column if not exists security_clearance_level text,
  add column if not exists billing_entity text,
  add column if not exists tax_id text;

update public.tenants
set home_region='ae-1'
where home_region is null or home_region='ap-northeast-1';

create index if not exists idx_tenants_region on public.tenants(home_region);
create index if not exists idx_tenants_contract_region on public.tenants(contract_type,home_region);

notify pgrst,'reload schema';
