begin;

create table if not exists public.mdi_threat_actors (
  id uuid primary key default gen_random_uuid(),
  actor_id text not null unique,
  name text not null,
  aliases jsonb not null default '[]'::jsonb,
  origin_country text,
  motivation text,
  sophistication text,
  first_seen timestamptz,
  last_seen timestamptz,
  target_sectors jsonb not null default '[]'::jsonb,
  target_countries jsonb not null default '[]'::jsonb,
  sources jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.mdi_threat_actors enable row level security;
revoke all on public.mdi_threat_actors from anon, authenticated;

create table if not exists public.mdi_actor_ttps (
  actor_id uuid not null references public.mdi_threat_actors(id) on delete cascade,
  technique_id text not null,
  confidence double precision not null default 0.7,
  source text,
  evidence jsonb not null default '{}'::jsonb,
  last_observed timestamptz,
  primary key(actor_id,technique_id)
);
alter table public.mdi_actor_ttps enable row level security;
revoke all on public.mdi_actor_ttps from anon, authenticated;

create table if not exists public.mdi_case_ttps (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  case_id uuid not null references public.crime_cases(id) on delete cascade,
  technique_id text not null,
  confidence double precision not null default 0.7,
  observed_at timestamptz not null default now(),
  unique(case_id,technique_id)
);
alter table public.mdi_case_ttps enable row level security;
revoke all on public.mdi_case_ttps from anon, authenticated;
create index if not exists mdi_case_ttps_tenant_case_idx on public.mdi_case_ttps(tenant_id,case_id,observed_at desc);

create table if not exists public.mdi_attribution (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  case_id uuid not null references public.crime_cases(id) on delete cascade,
  actor_id uuid references public.mdi_threat_actors(id) on delete set null,
  confidence double precision not null,
  method text not null,
  evidence jsonb not null default '{}'::jsonb,
  alternative_actors jsonb not null default '[]'::jsonb,
  computed_at timestamptz not null default now()
);
alter table public.mdi_attribution enable row level security;
revoke all on public.mdi_attribution from anon, authenticated;
create index if not exists mdi_attribution_tenant_case_idx on public.mdi_attribution(tenant_id,case_id,computed_at desc);

commit;