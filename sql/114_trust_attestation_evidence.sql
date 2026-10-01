-- 114_trust_attestation_evidence.sql
-- Cyclothone Trust Infrastructure: real evidence + attestation foundation.
-- No synthetic trust state is created. An attestation is only an evaluation
-- record over actual immutable measurements/evidence supplied by an authority.

create table if not exists public.trust_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,

  evidence_type text not null check (evidence_type in (
    'MEASUREMENT',
    'ATTESTATION_QUOTE',
    'SIGNATURE',
    'CERTIFICATE',
    'SECURE_BOOT',
    'TEE',
    'TPM',
    'CI_BUILD',
    'ARTIFACT',
    'RUNTIME',
    'DEPENDENCY',
    'CONFIGURATION',
    'POLICY',
    'NETWORK',
    'IDENTITY',
    'CUSTOM'
  )),

  source_type text not null check (source_type in (
    'LOCAL_AGENT',
    'REMOTE_AGENT',
    'PROVIDER',
    'TEE',
    'TPM',
    'CI_PIPELINE',
    'REGISTRY',
    'EXTERNAL_ATTESTER',
    'OPERATOR',
    'DEVICE',
    'CUSTOM'
  )),

  source_id text,
  content_type text,
  content_uri text,
  content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),

  -- Hash of the canonical evidence envelope, not merely the payload.
  evidence_hash text not null check (evidence_hash ~ '^[0-9a-f]{64}$'),

  collected_at timestamptz not null,
  expires_at timestamptz,

  signature_algorithm text,
  signer_key_id text,
  signature text,

  metadata jsonb not null default '{}'::jsonb
    check (jsonb_typeof(metadata) = 'object'),

  created_at timestamptz not null default now(),

  unique(subject_id, evidence_hash)
);

create index if not exists idx_trust_evidence_subject_time
  on public.trust_evidence(subject_id, collected_at desc);

create index if not exists idx_trust_evidence_tenant_type
  on public.trust_evidence(tenant_id, evidence_type, collected_at desc);

create index if not exists idx_trust_evidence_hash
  on public.trust_evidence(evidence_hash);

create table if not exists public.trust_attestations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,

  attestation_type text not null check (attestation_type in (
    'IDENTITY',
    'INTEGRITY',
    'RUNTIME',
    'MODEL',
    'AGENT',
    'DEVICE',
    'ENVIRONMENT',
    'EXECUTION',
    'COMPOSITE'
  )),

  verifier_type text not null check (verifier_type in (
    'CYCLOTHONE',
    'TEE_VERIFIER',
    'TPM_VERIFIER',
    'PROVIDER_VERIFIER',
    'EXTERNAL_ATTESTER',
    'CUSTOM'
  )),

  verifier_id text not null,
  verifier_version text,

  status text not null check (status in (
    'PENDING',
    'VERIFIED',
    'FAILED',
    'EXPIRED',
    'REVOKED'
  )),

  assurance_level text not null default 'NONE'
    check (assurance_level in (
      'NONE',
      'BASIC',
      'MEASURED',
      'HARDWARE_BACKED',
      'CRYPTOGRAPHIC'
    )),

  measurement_snapshot_hash text,
  evidence_root_hash text,

  valid_from timestamptz not null default now(),
  valid_until timestamptz,

  claims jsonb not null default '{}'::jsonb
    check (jsonb_typeof(claims) = 'object'),

  failure_reason text,

  created_at timestamptz not null default now(),
  verified_at timestamptz
);

create index if not exists idx_trust_attestations_subject_time
  on public.trust_attestations(subject_id, created_at desc);

create index if not exists idx_trust_attestations_status
  on public.trust_attestations(tenant_id, status, valid_until);

create table if not exists public.trust_attestation_evidence (
  attestation_id uuid not null references public.trust_attestations(id) on delete cascade,
  evidence_id uuid not null references public.trust_evidence(id) on delete restrict,
  role text not null check (role in (
    'PRIMARY',
    'MEASUREMENT',
    'IDENTITY',
    'INTEGRITY',
    'RUNTIME',
    'SIGNATURE',
    'SUPPORTING'
  )),
  created_at timestamptz not null default now(),
  primary key(attestation_id, evidence_id)
);

create index if not exists idx_trust_attestation_evidence_evidence
  on public.trust_attestation_evidence(evidence_id);

-- The evidence envelope is deterministic. This is the object Cyclothone will
-- later sign as a trust proof/certificate input.
create or replace function public.trust_evidence_hash(
  p_subject_id uuid,
  p_evidence_type text,
  p_source_type text,
  p_source_id text,
  p_content_hash text,
  p_collected_at timestamptz,
  p_expires_at timestamptz,
  p_signer_key_id text
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
          'evidence_type',p_evidence_type,
          'source_type',p_source_type,
          'source_id',p_source_id,
          'content_hash',p_content_hash,
          'collected_at',p_collected_at,
          'expires_at',p_expires_at,
          'signer_key_id',p_signer_key_id
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
$$;

create or replace function public.trust_record_evidence(
  p_subject_id uuid,
  p_evidence_type text,
  p_source_type text,
  p_source_id text,
  p_content_type text,
  p_content_uri text,
  p_content_hash text,
  p_collected_at timestamptz,
  p_expires_at timestamptz default null,
  p_signature_algorithm text default null,
  p_signer_key_id text default null,
  p_signature text default null,
  p_metadata jsonb default '{}'::jsonb
) returns public.trust_evidence
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  s public.trust_subjects;
  e public.trust_evidence;
  h text;
begin
  if p_subject_id is null
     or p_content_hash is null
     or p_content_hash !~ '^[0-9a-f]{64}$'
     or p_collected_at is null
     or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_trust_evidence';
  end if;

  select * into s
    from public.trust_subjects
   where id=p_subject_id
   for share;

  if not found then
    raise exception 'trust_subject_not_found';
  end if;

  if s.lifecycle_state in ('REVOKED','EXPIRED') then
    raise exception 'trust_subject_not_evidence_eligible';
  end if;

  h := public.trust_evidence_hash(
    p_subject_id,p_evidence_type,p_source_type,p_source_id,
    p_content_hash,p_collected_at,p_expires_at,p_signer_key_id
  );

  insert into public.trust_evidence(
    tenant_id,subject_id,evidence_type,source_type,source_id,
    content_type,content_uri,content_hash,evidence_hash,
    collected_at,expires_at,signature_algorithm,signer_key_id,signature,metadata
  ) values (
    s.tenant_id,p_subject_id,p_evidence_type,p_source_type,p_source_id,
    p_content_type,p_content_uri,p_content_hash,h,
    p_collected_at,p_expires_at,p_signature_algorithm,p_signer_key_id,p_signature,
    coalesce(p_metadata,'{}'::jsonb)
  )
  on conflict(subject_id,evidence_hash)
  do update set
    content_uri=coalesce(excluded.content_uri,public.trust_evidence.content_uri),
    metadata=excluded.metadata
  returning * into e;

  return e;
end;
$$;

revoke all on function public.trust_record_evidence(
  uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) from public,anon,authenticated;
grant execute on function public.trust_record_evidence(
  uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) to service_role;

-- Computes the evidence set used by an attestation. It intentionally hashes
-- references to immutable evidence rather than copying mutable payloads.
create or replace function public.trust_attestation_evidence_root(
  p_attestation_id uuid
) returns text
language sql
stable
set search_path = public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        coalesce(
          jsonb_agg(
            jsonb_build_object(
              'evidence_id',e.id,
              'evidence_hash',e.evidence_hash,
              'role',ae.role
            )
            order by e.id
          ),
          '[]'::jsonb
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
  from public.trust_attestation_evidence ae
  join public.trust_evidence e on e.id=ae.evidence_id
  where ae.attestation_id=p_attestation_id
$$;

-- Creates a real attestation only when referenced evidence exists and belongs
-- to the same subject. It does not automatically mark an attestation trusted:
-- the verifier must evaluate the evidence and supply the result.
create or replace function public.trust_create_attestation(
  p_subject_id uuid,
  p_attestation_type text,
  p_verifier_type text,
  p_verifier_id text,
  p_verifier_version text,
  p_evidence_ids uuid[],
  p_claims jsonb default '{}'::jsonb,
  p_valid_until timestamptz default null
) returns public.trust_attestations
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  s public.trust_subjects;
  a public.trust_attestations;
  e_id uuid;
  v_root text;
begin
  if p_subject_id is null
     or p_verifier_id is null
     or coalesce(array_length(p_evidence_ids,1),0) = 0
     or jsonb_typeof(coalesce(p_claims,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_attestation_request';
  end if;

  select * into s
    from public.trust_subjects
   where id=p_subject_id
   for share;

  if not found then
    raise exception 'trust_subject_not_found';
  end if;

  if exists (
    select 1
    from unnest(p_evidence_ids) x
    where not exists (
      select 1 from public.trust_evidence e
       where e.id=x and e.subject_id=p_subject_id
    )
  ) then
    raise exception 'attestation_evidence_subject_mismatch';
  end if;

  insert into public.trust_attestations(
    tenant_id,subject_id,attestation_type,verifier_type,verifier_id,
    verifier_version,status,claims,valid_until
  ) values (
    s.tenant_id,p_subject_id,p_attestation_type,p_verifier_type,p_verifier_id,
    p_verifier_version,'PENDING',coalesce(p_claims,'{}'::jsonb),p_valid_until
  )
  returning * into a;

  foreach e_id in array p_evidence_ids loop
    insert into public.trust_attestation_evidence(attestation_id,evidence_id,role)
    values(a.id,e_id,'SUPPORTING')
    on conflict do nothing;
  end loop;

  v_root := public.trust_attestation_evidence_root(a.id);

  update public.trust_attestations
     set evidence_root_hash=v_root
   where id=a.id
   returning * into a;

  return a;
end;
$$;

revoke all on function public.trust_create_attestation(
  uuid,text,text,text,text,uuid[],jsonb,timestamptz
) from public,anon,authenticated;
grant execute on function public.trust_create_attestation(
  uuid,text,text,text,text,uuid[],jsonb,timestamptz
) to service_role;

-- Verification is a separate authority operation. The verifier cannot mark
-- evidence verified unless the attestation still references the same immutable
-- evidence root.
create or replace function public.trust_verify_attestation(
  p_attestation_id uuid,
  p_status text,
  p_assurance_level text,
  p_claims jsonb,
  p_failure_reason text default null
) returns public.trust_attestations
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  a public.trust_attestations;
  v_root text;
begin
  if p_attestation_id is null
     or p_status not in ('VERIFIED','FAILED','EXPIRED','REVOKED')
     or p_assurance_level not in ('NONE','BASIC','MEASURED','HARDWARE_BACKED','CRYPTOGRAPHIC')
     or jsonb_typeof(coalesce(p_claims,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_attestation_verdict';
  end if;

  select * into a
    from public.trust_attestations
   where id=p_attestation_id
   for update;

  if not found then
    raise exception 'attestation_not_found';
  end if;

  v_root := public.trust_attestation_evidence_root(a.id);

  if a.evidence_root_hash is null or v_root <> a.evidence_root_hash then
    raise exception 'attestation_evidence_changed';
  end if;

  update public.trust_attestations
     set status=p_status,
         assurance_level=case when p_status='VERIFIED' then p_assurance_level else 'NONE' end,
         claims=coalesce(p_claims,'{}'::jsonb),
         failure_reason=case when p_status='FAILED' then p_failure_reason else null end,
         verified_at=now()
   where id=a.id
   returning * into a;

  return a;
end;
$$;

revoke all on function public.trust_verify_attestation(
  uuid,text,text,jsonb,text
) from public,anon,authenticated;
grant execute on function public.trust_verify_attestation(
  uuid,text,text,jsonb,text
) to service_role;

alter table public.trust_evidence enable row level security;
alter table public.trust_attestations enable row level security;
alter table public.trust_attestation_evidence enable row level security;

drop policy if exists trust_evidence_member_read on public.trust_evidence;
create policy trust_evidence_member_read on public.trust_evidence
for select to authenticated
using (
  tenant_id is null or exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id=trust_evidence.tenant_id
      and tm.user_id=auth.uid()
  )
);

drop policy if exists trust_attestations_member_read on public.trust_attestations;
create policy trust_attestations_member_read on public.trust_attestations
for select to authenticated
using (
  tenant_id is null or exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id=trust_attestations.tenant_id
      and tm.user_id=auth.uid()
  )
);

drop policy if exists trust_attestation_evidence_member_read on public.trust_attestation_evidence;
create policy trust_attestation_evidence_member_read on public.trust_attestation_evidence
for select to authenticated
using (
  exists (
    select 1
    from public.trust_attestations a
    join public.tenant_members tm on tm.tenant_id=a.tenant_id
    where a.id=trust_attestation_evidence.attestation_id
      and tm.user_id=auth.uid()
  )
);

revoke all on public.trust_evidence, public.trust_attestations, public.trust_attestation_evidence
from anon;
grant select on public.trust_evidence, public.trust_attestations, public.trust_attestation_evidence
to authenticated;

comment on table public.trust_evidence is
'Immutable evidence objects supporting Cyclothone attestations. Evidence is not itself a trust decision.';

comment on table public.trust_attestations is
'Verification records over immutable evidence. PENDING is not trusted; VERIFIED requires an authority verdict over an unchanged evidence root.';

comment on function public.trust_verify_attestation is
'Authority-only attestation verdict. Recomputes the evidence root before accepting the verdict.';
