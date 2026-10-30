-- Brand Protection deterministic integrity foundation v1.
-- Additive, tenant-bound, and compatible with the live numeric/first_seen_at schema.
-- Ingestion remains SECURITY INVOKER and service_role-only; no public SECURITY DEFINER API.

alter table public.brands
  add column if not exists trademarks text[] not null default '{}',
  add column if not exists logo_url text,
  add column if not exists region_code text;

alter table public.brand_threats
  add column if not exists verification_state text not null default 'candidate',
  add column if not exists evidence_sha256 text,
  add column if not exists verified_at timestamptz,
  add column if not exists false_positive_at timestamptz,
  add column if not exists takedown_provider text,
  add column if not exists takedown_ref text,
  add column if not exists takedown_at timestamptz,
  add column if not exists case_id uuid;

alter table public.brand_threats
  add constraint brand_threats_verification_state_check
  check (verification_state in ('candidate','verified','false_positive'))
  not valid;

alter table public.brand_threats
  validate constraint brand_threats_verification_state_check;

alter table public.brand_threats
  add constraint brand_threats_evidence_sha256_check
  check (evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$')
  not valid;

alter table public.brand_threats
  validate constraint brand_threats_evidence_sha256_check;

-- Enforce tenant/brand consistency at the relational boundary as well as the RPC.
create unique index if not exists brands_tenant_id_id_uq
  on public.brands(tenant_id,id);

alter table public.brand_threats
  add constraint brand_threats_tenant_brand_fk
  foreign key (tenant_id,brand_id)
  references public.brands(tenant_id,id)
  on delete cascade
  not valid;

alter table public.brand_threats
  validate constraint brand_threats_tenant_brand_fk;

create unique index if not exists brand_threats_tenant_id_id_uq\n  on public.brand_threats(tenant_id,id);\n\ncreate index if not exists brand_threats_tenant_verification_idx
  on public.brand_threats(tenant_id,verification_state,last_seen_at desc);

create index if not exists brand_threats_case_idx
  on public.brand_threats(case_id) where case_id is not null;

-- Append-only evidence manifest. Raw captures remain in controlled object storage;
-- this table records hashes and provenance, not untrusted HTML or screenshot bytes.
create table if not exists public.brand_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  brand_id uuid not null,
  threat_id uuid not null,
  evidence_type text not null,
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  source_url text,
  captured_at timestamptz not null default now(),
  provenance jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  foreign key (tenant_id,brand_id) references public.brands(tenant_id,id) on delete cascade,
  foreign key (tenant_id,threat_id) references public.brand_threats(tenant_id,id) on delete cascade
);
create index if not exists brand_evidence_tenant_threat_idx
  on public.brand_evidence(tenant_id,threat_id,captured_at desc);
alter table public.brand_evidence enable row level security;
revoke all on public.brand_evidence from anon,authenticated;
grant select,insert on public.brand_evidence to service_role;
revoke update,delete on public.brand_evidence from service_role;

-- Global trademark source catalogue and ingestion ledger. No records are fabricated:
-- only source adapters may populate these tables with source IDs and record hashes.
create table if not exists public.global_trademark_registry (
  id uuid primary key default gen_random_uuid(),
  trademark_name text not null,
  normalized_name text not null,
  owner_name text,
  office_code text not null,
  registration_number text not null,
  nice_classes integer[] not null default '{}',
  status text,
  priority_date date,
  source_record_id text,
  source_hash text not null check (source_hash ~ '^[0-9a-f]{64}$'),
  source_updated_at timestamptz,
  ingested_at timestamptz not null default now(),
  unique (office_code,registration_number)
);
create index if not exists global_trademark_name_trgm_idx
  on public.global_trademark_registry using gin (normalized_name gin_trgm_ops);
create index if not exists global_trademark_office_status_idx
  on public.global_trademark_registry(office_code,status);

create table if not exists public.brand_intel_sync_runs (
  id uuid primary key default gen_random_uuid(),
  source_code text not null,
  status text not null check (status in ('running','succeeded','partial','failed')),
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  source_cursor text,
  records_seen bigint not null default 0,
  records_inserted bigint not null default 0,
  records_updated bigint not null default 0,
  error_code text,
  error_summary text,
  source_metadata jsonb not null default '{}'::jsonb
);
create index if not exists brand_intel_sync_runs_source_time_idx
  on public.brand_intel_sync_runs(source_code,started_at desc);

create table if not exists public.brand_homoglyph_map (
  ascii_char text primary key check (length(ascii_char)=1),
  homoglyphs text[] not null
);
insert into public.brand_homoglyph_map(ascii_char,homoglyphs) values
 ('a',array['а','ɑ','α']), ('c',array['с','ϲ']), ('e',array['е','ε','℮']),
 ('i',array['і','ι']), ('j',array['ј']), ('o',array['о','ο','օ']),
 ('p',array['р','ρ']), ('s',array['ѕ']), ('x',array['х','χ']),
 ('y',array['у','γ'])
on conflict (ascii_char) do update set homoglyphs=excluded.homoglyphs;

create table if not exists public.brand_tld_risk_weights (
  tld text primary key,
  region_code text,
  weight numeric not null check (weight >= 0 and weight <= 5),
  source text not null,
  reviewed_at timestamptz
);
-- Seed only neutral/global defaults. Region-specific weights require customer context
-- and a reviewed policy; no unsupported country multipliers are preloaded.
insert into public.brand_tld_risk_weights(tld,region_code,weight,source)
values ('.com',null,1.0,'cyclothone_baseline'),('.net',null,1.0,'cyclothone_baseline'),
       ('.org',null,1.0,'cyclothone_baseline')
on conflict (tld) do nothing;

create table if not exists public.brand_threat_i18n (
  locale text not null,
  threat_type text not null,
  display_text text not null,
  PRIMARY KEY(locale,threat_type)
);
insert into public.brand_threat_i18n(locale,threat_type,display_text) values
 ('en','phishing_site','Phishing site impersonating a protected brand'),
 ('ar','phishing_site','موقع تصيد ينتحل علامة تجارية محمية'),
 ('fr','phishing_site','Site d’hameçonnage usurpant une marque protégée'),
 ('ja','phishing_site','保護対象ブランドを装うフィッシングサイト')
on conflict(locale,threat_type) do nothing;

-- Service-only access for global reference and sync tables; tenant-facing APIs
-- expose only tenant-filtered results after authorization.
do $$
declare t text;
begin
  foreach t in array array[
    'global_trademark_registry','brand_intel_sync_runs',
    'brand_homoglyph_map','brand_tld_risk_weights','brand_threat_i18n'
  ] loop
    execute format('alter table public.%I enable row level security',t);
    execute format('revoke all on public.%I from anon,authenticated',t);
    execute format('grant select,insert,update on public.%I to service_role',t);
  end loop;
end $$;

-- Replace the live 9-argument numeric RPC. The body validates tenant ownership,
-- preserves verified/false-positive decisions, and never trusts caller metadata
-- to promote a candidate.
create or replace function public.record_brand_threat(
  p_tenant uuid,
  p_brand uuid,
  p_kind text,
  p_identifier text,
  p_url text,
  p_platform text,
  p_similarity numeric,
  p_severity text,
  p_metadata jsonb
) returns uuid
language plpgsql
security invoker
set search_path = public, pg_temp
as $function$
declare
  v_id uuid;
  v_brand_tenant uuid;
  v_identifier text;
  v_evidence_hash text;
begin
  if p_tenant is null or p_brand is null then
    raise exception 'BRAND_TENANT_REQUIRED';
  end if;

  select tenant_id into v_brand_tenant
    from public.brands
   where id = p_brand;

  if v_brand_tenant is null or v_brand_tenant <> p_tenant then
    raise exception 'BRAND_TENANT_MISMATCH';
  end if;

  if p_kind is null or p_kind not in (
    'typosquat','homoglyph','combosquat','tld_swap','subdomain_trick',
    'social_handle','fake_app','fake_listing','phishing_page',
    'trademark_abuse','lookalike_logo','fake_recruitment','fake_support'
  ) then
    raise exception 'BRAND_THREAT_KIND_INVALID';
  end if;

  if p_severity is null or p_severity not in ('low','medium','high','critical') then
    raise exception 'BRAND_SEVERITY_INVALID';
  end if;

  if p_similarity is null or p_similarity < 0 or p_similarity > 1 then
    raise exception 'BRAND_SIMILARITY_INVALID';
  end if;

  v_identifier := lower(trim(coalesce(p_identifier,'')));
  if v_identifier = '' or length(v_identifier) > 2048 then
    raise exception 'BRAND_IDENTIFIER_INVALID';
  end if;

  v_evidence_hash := lower(coalesce(p_metadata->>'evidence_sha256',''));
  if v_evidence_hash !~ '^[0-9a-f]{64}$' then
    v_evidence_hash := null;
  end if;

  insert into public.brand_threats(
    tenant_id,brand_id,kind,identifier,url,platform,similarity,severity,
    metadata,verification_state,evidence_sha256
  ) values (
    p_tenant,p_brand,p_kind,v_identifier,p_url,p_platform,p_similarity,p_severity,
    coalesce(p_metadata,'{}'::jsonb) || jsonb_build_object(
      'verification_state','candidate',
      'verification_reason','source_observation_requires_independent_validation'
    ),
    'candidate',v_evidence_hash
  )
  on conflict (tenant_id,brand_id,kind,identifier) do update
    set url=coalesce(excluded.url,brand_threats.url),
        platform=coalesce(excluded.platform,brand_threats.platform),
        similarity=greatest(excluded.similarity,brand_threats.similarity),
        severity=case
          when brand_threats.severity='critical' or excluded.severity='critical' then 'critical'
          when brand_threats.severity='high' or excluded.severity='high' then 'high'
          when brand_threats.severity='medium' or excluded.severity='medium' then 'medium'
          else 'low' end,
        metadata=(brand_threats.metadata || excluded.metadata) ||\n          jsonb_build_object('verification_state',brand_threats.verification_state),
        last_seen_at=now(),
        evidence_sha256=coalesce(excluded.evidence_sha256,brand_threats.evidence_sha256),
        verification_state=brand_threats.verification_state
  returning id into v_id;

  return v_id;
end;
$function$;

revoke all on function public.record_brand_threat(uuid,uuid,text,text,text,text,numeric,text,jsonb)
  from public,anon,authenticated;
grant execute on function public.record_brand_threat(uuid,uuid,text,text,text,text,numeric,text,jsonb)
  to service_role;

-- Defense in depth: service collectors cannot rewrite/delete immutable evidence.
revoke update,delete on public.brand_evidence from service_role;

-- Takedown preparation is auditable but never dispatched automatically.
create table if not exists public.brand_takedown_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  brand_id uuid not null,
  threat_id uuid not null,
  provider text not null,
  subject text not null,
  report_body text not null,
  status text not null default 'prepared'
    check (status in ('prepared','authorized','dispatched','acknowledged','rejected','failed')),
  dispatch_requested boolean not null default false,
  created_by uuid,
  created_at timestamptz not null default now(),
  authorized_by uuid,
  authorized_at timestamptz,
  dispatched_at timestamptz,
  provider_reference text,
  error_code text,
  foreign key (tenant_id,brand_id) references public.brands(tenant_id,id) on delete cascade,
  foreign key (tenant_id,threat_id) references public.brand_threats(tenant_id,id) on delete cascade
);
create index if not exists brand_takedown_tenant_threat_idx
  on public.brand_takedown_requests(tenant_id,threat_id,created_at desc);
alter table public.brand_takedown_requests enable row level security;
revoke all on public.brand_takedown_requests from anon,authenticated;
grant select,insert,update on public.brand_takedown_requests to service_role;
