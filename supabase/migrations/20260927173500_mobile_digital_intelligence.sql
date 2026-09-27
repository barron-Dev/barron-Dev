create extension if not exists pgcrypto;

create table if not exists public.mobile_provider_accounts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  name text not null,
  provider_kind text not null check (provider_kind in ('gsma_open_gateway','operator','satellite','other')),
  base_url text not null,
  token_url text not null,
  client_id text not null,
  client_secret_ref text not null,
  scopes text[] not null default '{}',
  capabilities jsonb not null default '{}'::jsonb,
  country_codes text[] not null default '{}',
  enabled boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists mobile_provider_accounts_tenant_idx on public.mobile_provider_accounts(tenant_id, enabled);

create table if not exists public.mobile_authorizations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  app_id uuid not null references public.developer_apps(id) on delete cascade,
  subject_hash text not null,
  purpose text not null,
  authority_reference text not null,
  requested_by uuid,
  approved_by uuid,
  status text not null default 'pending' check (status in ('pending','approved','expired','revoked')),
  valid_from timestamptz not null,
  valid_to timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists mobile_authorizations_lookup_idx on public.mobile_authorizations(tenant_id, app_id, subject_hash, status);

create table if not exists public.mobile_queries (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  app_id uuid not null references public.developer_apps(id) on delete cascade,
  authorization_id uuid not null references public.mobile_authorizations(id) on delete restrict,
  subject_hash text not null,
  capabilities text[] not null,
  status text not null check (status in ('running','completed','failed')),
  error_code text,
  requested_at timestamptz not null default now(),
  completed_at timestamptz
);
create index if not exists mobile_queries_tenant_idx on public.mobile_queries(tenant_id, requested_at desc);

create table if not exists public.mobile_observations (
  id uuid primary key default gen_random_uuid(),
  query_id uuid not null references public.mobile_queries(id) on delete cascade,
  provider_id uuid not null references public.mobile_provider_accounts(id) on delete restrict,
  capability text not null,
  data jsonb not null,
  observed_at timestamptz not null default now()
);
create index if not exists mobile_observations_query_idx on public.mobile_observations(query_id, observed_at desc);

create table if not exists public.mobile_audit_log (
  id bigserial primary key,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  app_id uuid not null references public.developer_apps(id) on delete cascade,
  query_id uuid references public.mobile_queries(id) on delete set null,
  authorization_id uuid references public.mobile_authorizations(id) on delete set null,
  action text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists mobile_audit_log_tenant_idx on public.mobile_audit_log(tenant_id, created_at desc);

alter table public.mobile_provider_accounts enable row level security;
alter table public.mobile_authorizations enable row level security;
alter table public.mobile_queries enable row level security;
alter table public.mobile_observations enable row level security;
alter table public.mobile_audit_log enable row level security;

create policy mobile_provider_accounts_tenant on public.mobile_provider_accounts using (tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy mobile_authorizations_tenant on public.mobile_authorizations using (tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy mobile_queries_tenant on public.mobile_queries using (tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy mobile_observations_tenant on public.mobile_observations using (query_id in (select id from public.mobile_queries where tenant_id=(auth.jwt()->>'tenant_id')::uuid));
create policy mobile_audit_log_tenant on public.mobile_audit_log using (tenant_id=(auth.jwt()->>'tenant_id')::uuid);

revoke all on public.mobile_provider_accounts from anon, authenticated;
revoke all on public.mobile_authorizations from anon, authenticated;
revoke all on public.mobile_queries from anon, authenticated;
revoke all on public.mobile_observations from anon, authenticated;
revoke all on public.mobile_audit_log from anon, authenticated;
