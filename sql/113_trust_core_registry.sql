-- 113_trust_core_registry.sql
-- Cyclothone Trust Infrastructure foundation.
-- Extends the existing AI identity/execution foundation; it does not duplicate
-- models, agents, runtimes, devices, missions, or AI runs.
--
-- Principle:
--   declared identity != measured identity
--   a trust subject may exist without being trusted
--   measurements are immutable observations
--   certification/attestation is built on top of this registry in later migrations

create table if not exists public.trust_subjects (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,

  subject_kind text not null check (subject_kind in (
    'MODEL',
    'MODEL_VERSION',
    'AGENT',
    'AGENT_VERSION',
    'RUNTIME',
    'RUNTIME_VERSION',
    'DEVICE',
    'ENVIRONMENT',
    'TOOL',
    'APPLICATION',
    'EXTERNAL_AGENT',
    'TRUST_NODE'
  )),

  -- Stable reference into the existing system or an external provider.
  -- Examples: existing model UUID/text id, agent UUID, device UUID, or
  -- customer-supplied external identifier.
  external_ref text not null check (length(trim(external_ref)) between 1 and 512),

  display_name text,
  provider_id text,
  version text,

  -- Canonical identity material supplied by the registry owner. This is
  -- descriptive identity only; trust is established from measurements and
  -- attestation.
  identity_document jsonb not null default '{}'::jsonb
    check (jsonb_typeof(identity_document) = 'object'),

  -- Optional public key for the subject/node. Key purpose is explicit so the
  -- trust layer never silently reuses a command/device key.
  public_key_algorithm text,
  public_key text,
  key_id text,

  lifecycle_state text not null default 'REGISTERED'
    check (lifecycle_state in (
      'REGISTERED',
      'ACTIVE',
      'SUSPENDED',
      'REVOKED',
      'EXPIRED'
    )),

  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  unique (tenant_id, subject_kind, external_ref)
);

create index if not exists idx_trust_subjects_tenant_kind
  on public.trust_subjects(tenant_id, subject_kind, lifecycle_state);

create index if not exists idx_trust_subjects_provider
  on public.trust_subjects(tenant_id, provider_id);

create table if not exists public.trust_subject_aliases (
  id uuid primary key default gen_random_uuid(),
  subject_id uuid not null references public.trust_subjects(id) on delete cascade,
  alias_type text not null check (alias_type in (
    'MODEL_ID',
    'MODEL_VERSION_ID',
    'AGENT_ID',
    'RUNTIME_ID',
    'DEVICE_ID',
    'PROVIDER_ID',
    'EXTERNAL_ID',
    'URI'
  )),
  alias_value text not null check (length(trim(alias_value)) between 1 and 1024),
  created_at timestamptz not null default now(),
  unique (alias_type, alias_value)
);

create index if not exists idx_trust_subject_aliases_subject
  on public.trust_subject_aliases(subject_id);

create table if not exists public.trust_measurements (
  id uuid primary key default gen_random_uuid(),
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  tenant_id uuid references public.tenants(id) on delete cascade,

  measurement_type text not null check (measurement_type in (
    'ARTIFACT_HASH',
    'WEIGHTS_HASH',
    'TOKENIZER_HASH',
    'RUNTIME_HASH',
    'CONTAINER_HASH',
    'DEPENDENCY_HASH',
    'CONFIGURATION_HASH',
    'SOURCE_HASH',
    'BINARY_HASH',
    'FIRMWARE_HASH',
    'BOOT_STATE',
    'SECURE_BOOT_STATE',
    'TEE_QUOTE',
    'TPM_QUOTE',
    'HOST_IDENTITY',
    'NETWORK_IDENTITY',
    'CAPABILITY_SET',
    'PERMISSION_SET',
    'TOOL_SET',
    'ENVIRONMENT_STATE',
    'CUSTOM'
  )),

  algorithm text not null check (algorithm in (
    'SHA-256',
    'SHA-384',
    'SHA-512',
    'BLAKE2B-256',
    'BLAKE3',
    'ED25519',
    'TPM2',
    'TEE',
    'CUSTOM'
  )),

  -- Hashes are normalized to lowercase hexadecimal where applicable.
  measurement_value text not null check (length(trim(measurement_value)) between 1 and 4096),
  measurement_hash text not null check (measurement_hash ~ '^[0-9a-f]{64}$'),

  source_type text not null check (source_type in (
    'LOCAL_AGENT',
    'REMOTE_AGENT',
    'PROVIDER',
    'TEE',
    'TPM',
    'SECURE_BOOT',
    'CI_PIPELINE',
    'REGISTRY',
    'OPERATOR',
    'EXTERNAL_ATTESTER',
    'CUSTOM'
  )),
  source_id text,

  collected_at timestamptz not null,
  received_at timestamptz not null default now(),

  evidence_uri text,
  evidence_hash text check (
    evidence_hash is null or evidence_hash ~ '^[0-9a-f]{64}$'
  ),

  metadata jsonb not null default '{}'::jsonb
    check (jsonb_typeof(metadata) = 'object'),

  -- Immutable observation sequence for deterministic provenance.
  sequence_no bigint not null generated always as identity,

  created_at timestamptz not null default now(),

  unique (subject_id, measurement_type, measurement_hash, collected_at)
);

create index if not exists idx_trust_measurements_subject_time
  on public.trust_measurements(subject_id, collected_at desc);

create index if not exists idx_trust_measurements_tenant_type
  on public.trust_measurements(tenant_id, measurement_type, collected_at desc);

create index if not exists idx_trust_measurements_hash
  on public.trust_measurements(measurement_hash);

-- Immutable measurement records. Corrections are represented by a new
-- measurement, never by UPDATE/DELETE.
create or replace function public.trust_measurements_immutable()
returns trigger
language plpgsql
set search_path = public,pg_catalog
as $$
begin
  raise exception 'trust_measurements_are_immutable';
end;
$$;

drop trigger if exists trust_measurements_no_update on public.trust_measurements;
create trigger trust_measurements_no_update
before update or delete on public.trust_measurements
for each row execute function public.trust_measurements_immutable();

-- Canonical measurement digest. This proves exactly which subject, measurement
-- type, algorithm, value and collection time were recorded.
create or replace function public.trust_measurement_hash(
  p_subject_id uuid,
  p_measurement_type text,
  p_algorithm text,
  p_measurement_value text,
  p_source_type text,
  p_source_id text,
  p_collected_at timestamptz,
  p_evidence_hash text
) returns text
language sql
immutable
strict
set search_path = public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        jsonb_build_object(
          'subject_id',p_subject_id,
          'measurement_type',p_measurement_type,
          'algorithm',p_algorithm,
          'measurement_value',p_measurement_value,
          'source_type',p_source_type,
          'source_id',p_source_id,
          'collected_at',p_collected_at,
          'evidence_hash',p_evidence_hash
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
$$;

-- Service-role-only write authority. Public clients must never be able to
-- fabricate a trust measurement by directly inserting rows.
create or replace function public.trust_record_measurement(
  p_subject_id uuid,
  p_measurement_type text,
  p_algorithm text,
  p_measurement_value text,
  p_source_type text,
  p_source_id text default null,
  p_collected_at timestamptz default now(),
  p_evidence_uri text default null,
  p_evidence_hash text default null,
  p_metadata jsonb default '{}'::jsonb
) returns public.trust_measurements
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  s public.trust_subjects;
  m public.trust_measurements;
  h text;
begin
  if p_subject_id is null
     or p_measurement_type is null
     or p_algorithm is null
     or p_measurement_value is null
     or p_source_type is null
     or p_collected_at is null
     or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_trust_measurement';
  end if;

  select * into s
    from public.trust_subjects
   where id = p_subject_id
   for share;

  if not found then
    raise exception 'trust_subject_not_found';
  end if;

  if s.lifecycle_state in ('REVOKED','EXPIRED') then
    raise exception 'trust_subject_not_measureable';
  end if;

  h := public.trust_measurement_hash(
    p_subject_id,
    p_measurement_type,
    p_algorithm,
    p_measurement_value,
    p_source_type,
    p_source_id,
    p_collected_at,
    p_evidence_hash
  );

  insert into public.trust_measurements(
    subject_id,
    tenant_id,
    measurement_type,
    algorithm,
    measurement_value,
    measurement_hash,
    source_type,
    source_id,
    collected_at,
    evidence_uri,
    evidence_hash,
    metadata
  ) values (
    p_subject_id,
    s.tenant_id,
    p_measurement_type,
    p_algorithm,
    p_measurement_value,
    h,
    p_source_type,
    p_source_id,
    p_collected_at,
    p_evidence_uri,
    p_evidence_hash,
    coalesce(p_metadata,'{}'::jsonb)
  )
  on conflict (subject_id, measurement_type, measurement_hash, collected_at)
  do update set received_at = public.trust_measurements.received_at
  returning * into m;

  return m;
end;
$$;

revoke all on function public.trust_record_measurement(
  uuid,text,text,text,text,text,timestamptz,text,text,jsonb
) from public,anon,authenticated;
grant execute on function public.trust_record_measurement(
  uuid,text,text,text,text,text,timestamptz,text,text,jsonb
) to service_role;

-- Subject registration is also service-role-only. External AI onboarding will
-- use a backend API which validates the caller before invoking this authority.
create or replace function public.trust_register_subject(
  p_tenant_id uuid,
  p_subject_kind text,
  p_external_ref text,
  p_display_name text default null,
  p_provider_id text default null,
  p_version text default null,
  p_identity_document jsonb default '{}'::jsonb,
  p_public_key_algorithm text default null,
  p_public_key text default null,
  p_key_id text default null,
  p_created_by uuid default null
) returns public.trust_subjects
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  s public.trust_subjects;
begin
  if p_subject_kind is null
     or p_external_ref is null
     or length(trim(p_external_ref)) = 0
     or length(p_external_ref) > 512
     or jsonb_typeof(coalesce(p_identity_document,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_trust_subject';
  end if;

  insert into public.trust_subjects(
    tenant_id,
    subject_kind,
    external_ref,
    display_name,
    provider_id,
    version,
    identity_document,
    public_key_algorithm,
    public_key,
    key_id,
    created_by
  ) values (
    p_tenant_id,
    p_subject_kind,
    trim(p_external_ref),
    nullif(trim(p_display_name),''),
    nullif(trim(p_provider_id),''),
    nullif(trim(p_version),''),
    coalesce(p_identity_document,'{}'::jsonb),
    nullif(trim(p_public_key_algorithm),''),
    nullif(trim(p_public_key),''),
    nullif(trim(p_key_id),''),
    p_created_by
  )
  on conflict (tenant_id, subject_kind, external_ref)
  do update set
    display_name = coalesce(excluded.display_name, public.trust_subjects.display_name),
    provider_id = coalesce(excluded.provider_id, public.trust_subjects.provider_id),
    version = coalesce(excluded.version, public.trust_subjects.version),
    identity_document = excluded.identity_document,
    public_key_algorithm = coalesce(excluded.public_key_algorithm, public.trust_subjects.public_key_algorithm),
    public_key = coalesce(excluded.public_key, public.trust_subjects.public_key),
    key_id = coalesce(excluded.key_id, public.trust_subjects.key_id),
    updated_at = now()
  returning * into s;

  return s;
end;
$$;

revoke all on function public.trust_register_subject(
  uuid,text,text,text,text,text,jsonb,text,text,text,uuid
) from public,anon,authenticated;
grant execute on function public.trust_register_subject(
  uuid,text,text,text,text,text,jsonb,text,text,text,uuid
) to service_role;

-- RLS: tenants may inspect their own registry; writes remain authority-only.
alter table public.trust_subjects enable row level security;
alter table public.trust_subject_aliases enable row level security;
alter table public.trust_measurements enable row level security;

drop policy if exists trust_subjects_member_read on public.trust_subjects;
create policy trust_subjects_member_read on public.trust_subjects
for select to authenticated
using (
  tenant_id is null
  or exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id = trust_subjects.tenant_id
      and tm.user_id = auth.uid()
  )
);

drop policy if exists trust_subject_aliases_member_read on public.trust_subject_aliases;
create policy trust_subject_aliases_member_read on public.trust_subject_aliases
for select to authenticated
using (
  exists (
    select 1
    from public.trust_subjects s
    join public.tenant_members tm on tm.tenant_id = s.tenant_id
    where s.id = trust_subject_aliases.subject_id
      and tm.user_id = auth.uid()
  )
);

drop policy if exists trust_measurements_member_read on public.trust_measurements;
create policy trust_measurements_member_read on public.trust_measurements
for select to authenticated
using (
  tenant_id is null
  or exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id = trust_measurements.tenant_id
      and tm.user_id = auth.uid()
  )
);

revoke all on public.trust_subjects, public.trust_subject_aliases, public.trust_measurements
from anon;

grant select on public.trust_subjects, public.trust_subject_aliases, public.trust_measurements
to authenticated;

comment on table public.trust_subjects is
'Canonical Cyclothone trust identity registry. Existing AI/device identities remain authoritative; this table binds them into the trust domain.';

comment on table public.trust_measurements is
'Immutable real-world measurements and attestation inputs. A measurement is evidence, not a trust decision.';

comment on function public.trust_record_measurement is
'Authority-only insertion of immutable trust measurements. No client role can fabricate trust evidence.';

comment on function public.trust_register_subject is
'Authority-only registration/upsert of a trust subject. Registration never implies certification.';
