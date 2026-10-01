-- GIRIL global reference and onboarding foundation v1
-- Applied to the live Supabase project before repository synchronization.
-- No reference or customer data is seeded here. Only authoritative-source
-- structures are created; population happens from verified source connectors.

begin;

create table if not exists public.giril_ref_sources (
  id uuid primary key default gen_random_uuid(),
  source_key text not null unique,
  name text not null,
  authority_level text not null check (authority_level in ('PRIMARY','REGULATORY','OFFICIAL','SECONDARY')),
  source_kind text not null check (source_kind in ('REGISTRY','GOVERNMENT','STANDARDS','TELECOM','DNS','NETWORK','IDENTITY','OTHER')),
  jurisdiction_code text,
  source_url text,
  api_base_url text,
  licensing_notes text,
  update_policy text,
  status text not null default 'UNINITIALIZED' check (status in ('UNINITIALIZED','ACTIVE','DEGRADED','RETIRED')),
  last_sync_at timestamptz,
  next_sync_due_at timestamptz,
  source_version text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.giril_ref_countries (
  iso2 char(2) primary key,
  iso3 char(3) unique,
  numeric_code char(3),
  name text not null,
  official_name text,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','INACTIVE','HISTORICAL')),
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  valid_from timestamptz,
  valid_to timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.giril_ref_subdivisions (
  id uuid primary key default gen_random_uuid(),
  country_iso2 char(2) not null references public.giril_ref_countries(iso2) on delete restrict,
  code text not null,
  name text not null,
  subdivision_type text,
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  valid_from timestamptz,
  valid_to timestamptz,
  unique(country_iso2,code)
);

create table if not exists public.giril_ref_registries (
  id uuid primary key default gen_random_uuid(),
  country_iso2 char(2) references public.giril_ref_countries(iso2) on delete restrict,
  subdivision_id uuid references public.giril_ref_subdivisions(id) on delete restrict,
  registry_key text not null unique,
  registry_name text not null,
  registry_type text not null check (registry_type in ('COMPANY','BUSINESS','NONPROFIT','SECURITIES','TAX','PROFESSIONAL','GOVERNMENT','OTHER')),
  authority_level text not null check (authority_level in ('PRIMARY','REGULATORY','OFFICIAL')),
  public_lookup_available boolean not null default false,
  api_available boolean not null default false,
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  source_url text,
  api_base_url text,
  verification_method text,
  freshness_ttl interval,
  status text not null default 'UNINITIALIZED' check (status in ('UNINITIALIZED','ACTIVE','DEGRADED','RETIRED')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check(country_iso2 is not null or subdivision_id is not null)
);

create table if not exists public.giril_ref_company_id_rules (
  id uuid primary key default gen_random_uuid(),
  registry_id uuid not null references public.giril_ref_registries(id) on delete cascade,
  identifier_name text not null,
  identifier_type text not null,
  pattern text,
  min_length integer check(min_length is null or min_length>0),
  max_length integer check(max_length is null or max_length>=coalesce(min_length,1)),
  checksum_algorithm text,
  normalization_rule text,
  required boolean not null default true,
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  effective_from timestamptz,
  effective_to timestamptz,
  rule_version text not null,
  unique(registry_id,identifier_name,rule_version)
);

create table if not exists public.giril_ref_id_doc_rules (
  id uuid primary key default gen_random_uuid(),
  country_iso2 char(2) not null references public.giril_ref_countries(iso2) on delete restrict,
  document_type text not null,
  issuing_authority text,
  document_code text,
  pattern text,
  checksum_algorithm text,
  mrz_supported boolean,
  nfc_supported boolean,
  required_fields jsonb not null default '[]'::jsonb check(jsonb_typeof(required_fields)='array'),
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  rule_version text not null,
  effective_from timestamptz,
  effective_to timestamptz,
  unique(country_iso2,document_type,document_code,rule_version)
);
create unique index if not exists giril_id_doc_rules_uq_null_code
  on public.giril_ref_id_doc_rules(country_iso2,document_type,coalesce(document_code,''),rule_version);

create table if not exists public.giril_ref_numbering_plans (
  id uuid primary key default gen_random_uuid(),
  country_iso2 char(2) not null references public.giril_ref_countries(iso2) on delete restrict,
  country_calling_code text not null,
  national_prefix text,
  trunk_prefix text,
  national_number_pattern text,
  mobile_patterns jsonb not null default '[]'::jsonb check(jsonb_typeof(mobile_patterns)='array'),
  fixed_patterns jsonb not null default '[]'::jsonb check(jsonb_typeof(fixed_patterns)='array'),
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  rule_version text not null,
  effective_from timestamptz,
  effective_to timestamptz,
  unique(country_iso2,rule_version)
);

create table if not exists public.giril_ref_email_domains (
  domain text primary key,
  classification text not null check(classification in ('FREE_MAIL','DISPOSABLE','EDUCATION','GOVERNMENT','MILITARY','OTHER_PUBLIC','UNKNOWN')),
  organization_hint text,
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  confidence numeric(5,4) check(confidence is null or confidence between 0 and 1),
  effective_from timestamptz,
  effective_to timestamptz,
  rule_version text not null,
  updated_at timestamptz not null default now(),
  check(domain=lower(domain) and length(domain) between 1 and 253)
);

create table if not exists public.giril_ref_domain_rules (
  id uuid primary key default gen_random_uuid(),
  domain_suffix text not null,
  rule_type text not null check(rule_type in ('PUBLIC_SUFFIX','GOVERNMENT','MILITARY','EDUCATION','DISPOSABLE','FREE_MAIL','RESERVED','OTHER')),
  registrable_domain_required boolean not null default true,
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  rule_version text not null,
  effective_from timestamptz,
  effective_to timestamptz,
  unique(domain_suffix,rule_type,rule_version),
  check(domain_suffix=lower(domain_suffix) and length(domain_suffix) between 1 and 253)
);

create table if not exists public.giril_ref_asn (
  asn bigint primary key check(asn>0),
  as_name text,
  country_iso2 char(2) references public.giril_ref_countries(iso2) on delete restrict,
  network_type text check(network_type is null or network_type in ('ISP','CLOUD','HOSTING','GOVERNMENT','EDUCATION','ENTERPRISE','OTHER','UNKNOWN')),
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  confidence numeric(5,4) check(confidence is null or confidence between 0 and 1),
  effective_from timestamptz,
  effective_to timestamptz,
  updated_at timestamptz not null default now()
);

create table if not exists public.giril_ref_sync_runs (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references public.giril_ref_sources(id) on delete restrict,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  status text not null check(status in ('RUNNING','SUCCEEDED','FAILED','PARTIAL')),
  source_version text,
  records_seen bigint not null default 0 check(records_seen>=0),
  records_changed bigint not null default 0 check(records_changed>=0),
  error_summary text,
  manifest_hash text,
  created_at timestamptz not null default now()
);

create table if not exists public.giril_onboarding_cases (
  id uuid primary key default gen_random_uuid(),
  applicant_user_id uuid not null references auth.users(id) on delete cascade,
  requested_name text not null check(length(trim(requested_name)) between 1 and 240),
  email text not null check(length(trim(email)) between 3 and 320),
  phone text not null check(length(trim(phone)) between 3 and 64),
  subject_kind text check(subject_kind is null or subject_kind in ('INDIVIDUAL','COMPANY','GOVERNMENT','SECURITY_PROVIDER','DEVELOPER','PARTNER','OTHER')),
  country_iso2 char(2) references public.giril_ref_countries(iso2) on delete restrict,
  state text not null default 'REGISTERED' check(state in ('REGISTERED','COLLECTING','VERIFYING','TRUST_REVIEW','CONTROL_REVIEW','ADMITTED','REJECTED','MANUAL_REVIEW')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists giril_onboarding_cases_open_user_uq
  on public.giril_onboarding_cases(applicant_user_id) where state not in ('ADMITTED','REJECTED');

create table if not exists public.giril_verification_checks (
  id uuid primary key default gen_random_uuid(),
  onboarding_case_id uuid not null references public.giril_onboarding_cases(id) on delete cascade,
  check_type text not null check(check_type in ('FORMAT','EMAIL','PHONE','DOMAIN','COMPANY_REGISTRY','ID_DOCUMENT','GOVERNMENT_REGISTRY','TAX_REGISTRY','OTHER')),
  target_hash text not null check(target_hash ~ '^[0-9a-f]{64}$'),
  registry_id uuid references public.giril_ref_registries(id) on delete restrict,
  source_id uuid references public.giril_ref_sources(id) on delete restrict,
  identity_verification_id uuid references public.identity_verifications(id) on delete set null,
  trust_evidence_id uuid references public.trust_evidence(id) on delete set null,
  status text not null default 'PENDING' check(status in ('PENDING','RUNNING','VERIFIED','NOT_VERIFIED','UNAVAILABLE','MANUAL_REVIEW','ERROR')),
  verifier_version text,
  verification_method text,
  requested_at timestamptz not null default now(),
  completed_at timestamptz,
  expires_at timestamptz,
  failure_reason text,
  metadata jsonb not null default '{}'::jsonb check(jsonb_typeof(metadata)='object')
);

create index if not exists giril_registries_country_idx on public.giril_ref_registries(country_iso2,status);
create index if not exists giril_company_rules_registry_idx on public.giril_ref_company_id_rules(registry_id);
create index if not exists giril_numbering_country_idx on public.giril_ref_numbering_plans(country_iso2);
create index if not exists giril_sync_source_idx on public.giril_ref_sync_runs(source_id,started_at desc);
create index if not exists giril_onboarding_user_idx on public.giril_onboarding_cases(applicant_user_id,created_at desc);
create index if not exists giril_checks_case_idx on public.giril_verification_checks(onboarding_case_id,requested_at desc);

alter table public.giril_ref_sources enable row level security;
alter table public.giril_ref_countries enable row level security;
alter table public.giril_ref_subdivisions enable row level security;
alter table public.giril_ref_registries enable row level security;
alter table public.giril_ref_company_id_rules enable row level security;
alter table public.giril_ref_id_doc_rules enable row level security;
alter table public.giril_ref_numbering_plans enable row level security;
alter table public.giril_ref_email_domains enable row level security;
alter table public.giril_ref_domain_rules enable row level security;
alter table public.giril_ref_asn enable row level security;
alter table public.giril_ref_sync_runs enable row level security;
alter table public.giril_onboarding_cases enable row level security;
alter table public.giril_verification_checks enable row level security;

drop policy if exists giril_ref_sources_read on public.giril_ref_sources;
create policy giril_ref_sources_read on public.giril_ref_sources for select to authenticated using(true);
drop policy if exists giril_ref_countries_read on public.giril_ref_countries;
create policy giril_ref_countries_read on public.giril_ref_countries for select to authenticated using(true);
drop policy if exists giril_ref_subdivisions_read on public.giril_ref_subdivisions;
create policy giril_ref_subdivisions_read on public.giril_ref_subdivisions for select to authenticated using(true);
drop policy if exists giril_ref_registries_read on public.giril_ref_registries;
create policy giril_ref_registries_read on public.giril_ref_registries for select to authenticated using(true);
drop policy if exists giril_ref_company_id_rules_read on public.giril_ref_company_id_rules;
create policy giril_ref_company_id_rules_read on public.giril_ref_company_id_rules for select to authenticated using(true);
drop policy if exists giril_ref_id_doc_rules_read on public.giril_ref_id_doc_rules;
create policy giril_ref_id_doc_rules_read on public.giril_ref_id_doc_rules for select to authenticated using(true);
drop policy if exists giril_ref_numbering_plans_read on public.giril_ref_numbering_plans;
create policy giril_ref_numbering_plans_read on public.giril_ref_numbering_plans for select to authenticated using(true);
drop policy if exists giril_ref_email_domains_read on public.giril_ref_email_domains;
create policy giril_ref_email_domains_read on public.giril_ref_email_domains for select to authenticated using(true);
drop policy if exists giril_ref_domain_rules_read on public.giril_ref_domain_rules;
create policy giril_ref_domain_rules_read on public.giril_ref_domain_rules for select to authenticated using(true);
drop policy if exists giril_ref_asn_read on public.giril_ref_asn;
create policy giril_ref_asn_read on public.giril_ref_asn for select to authenticated using(true);

create policy giril_ref_sync_runs_service_role on public.giril_ref_sync_runs for all to service_role using(true) with check(true);

drop policy if exists giril_onboarding_case_owner_read on public.giril_onboarding_cases;
create policy giril_onboarding_case_owner_read on public.giril_onboarding_cases for select to authenticated using(applicant_user_id=(select auth.uid()));
drop policy if exists giril_verification_check_owner_read on public.giril_verification_checks;
create policy giril_verification_check_owner_read on public.giril_verification_checks for select to authenticated using(
 exists(select 1 from public.giril_onboarding_cases c where c.id=giril_verification_checks.onboarding_case_id and c.applicant_user_id=(select auth.uid()))
);

revoke all on public.giril_ref_sources,public.giril_ref_countries,public.giril_ref_subdivisions,public.giril_ref_registries,public.giril_ref_company_id_rules,
 public.giril_ref_id_doc_rules,public.giril_ref_numbering_plans,public.giril_ref_email_domains,public.giril_ref_domain_rules,public.giril_ref_asn,
 public.giril_ref_sync_runs,public.giril_onboarding_cases,public.giril_verification_checks from anon;
grant select on public.giril_ref_sources,public.giril_ref_countries,public.giril_ref_subdivisions,public.giril_ref_registries,public.giril_ref_company_id_rules,
 public.giril_ref_id_doc_rules,public.giril_ref_numbering_plans,public.giril_ref_email_domains,public.giril_ref_domain_rules,public.giril_ref_asn to authenticated;
revoke insert,update,delete on public.giril_ref_sources,public.giril_ref_countries,public.giril_ref_subdivisions,public.giril_ref_registries,public.giril_ref_company_id_rules,
 public.giril_ref_id_doc_rules,public.giril_ref_numbering_plans,public.giril_ref_email_domains,public.giril_ref_domain_rules,public.giril_ref_asn,
 public.giril_ref_sync_runs,public.giril_onboarding_cases,public.giril_verification_checks from anon,authenticated;

commit;