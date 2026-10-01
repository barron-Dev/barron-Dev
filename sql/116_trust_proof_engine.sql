-- 116_trust_proof_engine.sql
-- Cyclothone Trust Proof / Provenance Engine.
-- This block creates deterministic, immutable proof objects over real trust inputs.
-- It deliberately does NOT issue certificates or invent signatures.
-- A later signing authority will sign the canonical proof_hash.

create table if not exists public.trust_proofs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,

  state_snapshot_id uuid not null references public.trust_state_snapshots(id) on delete restrict,
  attestation_id uuid references public.trust_attestations(id) on delete restrict,

  state text not null check (state in (
    'UNKNOWN','REGISTERED','OBSERVED','ATTESTED','VERIFIED',
    'DEGRADED','SUSPENDED','REVOKED','EXPIRED'
  )),
  assurance_level text not null check (assurance_level in (
    'NONE','BASIC','MEASURED','HARDWARE_BACKED','CRYPTOGRAPHIC'
  )),

  measurement_root_hash text not null check (measurement_root_hash ~ '^[0-9a-f]{64}$'),
  evidence_root_hash text check (
    evidence_root_hash is null or evidence_root_hash ~ '^[0-9a-f]{64}$'
  ),
  attestation_root_hash text check (
    attestation_root_hash is null or attestation_root_hash ~ '^[0-9a-f]{64}$'
  ),

  subject_identity_hash text not null check (subject_identity_hash ~ '^[0-9a-f]{64}$'),
  proof_hash text not null check (proof_hash ~ '^[0-9a-f]{64}$'),

  -- Signature fields remain null until a dedicated signing authority exists.
  signature_algorithm text,
  signer_key_id text,
  signature text,

  claims jsonb not null default '{}'::jsonb
    check (jsonb_typeof(claims) = 'object'),

  created_at timestamptz not null default now()
);

create unique index if not exists uq_trust_proofs_proof_hash
  on public.trust_proofs(proof_hash);

create index if not exists idx_trust_proofs_subject_time
  on public.trust_proofs(subject_id, created_at desc);

create index if not exists idx_trust_proofs_tenant_time
  on public.trust_proofs(tenant_id, created_at desc);

-- Proof records are immutable. A new state/evidence set produces a new proof.
create or replace function public.trust_proofs_immutable()
returns trigger
language plpgsql
set search_path=public,pg_catalog
as $$
begin
  raise exception 'trust_proofs_are_immutable';
end;
$$;

drop trigger if exists trust_proofs_no_update on public.trust_proofs;
create trigger trust_proofs_no_update
before update or delete on public.trust_proofs
for each row execute function public.trust_proofs_immutable();

-- Deterministic root over the exact immutable measurement records available to
-- the subject at evaluation time. Sequence number makes ordering explicit.
create or replace function public.trust_measurement_root(
  p_subject_id uuid,
  p_through timestamptz
) returns text
language sql
stable
set search_path=public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        coalesce(
          jsonb_agg(
            jsonb_build_object(
              'id',m.id,
              'sequence_no',m.sequence_no,
              'measurement_hash',m.measurement_hash,
              'measurement_type',m.measurement_type,
              'collected_at',m.collected_at
            )
            order by m.sequence_no
          ),
          '[]'::jsonb
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
  from public.trust_measurements m
  where m.subject_id=p_subject_id
    and m.created_at <= p_through
$$;

create or replace function public.trust_evidence_root(
  p_subject_id uuid,
  p_through timestamptz
) returns text
language sql
stable
set search_path=public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        coalesce(
          jsonb_agg(
            jsonb_build_object(
              'id',e.id,
              'evidence_hash',e.evidence_hash,
              'evidence_type',e.evidence_type,
              'collected_at',e.collected_at
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
  from public.trust_evidence e
  where e.subject_id=p_subject_id
    and e.created_at <= p_through
$$;

create or replace function public.trust_attestation_root(
  p_attestation_id uuid
) returns text
language sql
stable
set search_path=public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        jsonb_build_object(
          'attestation_id',a.id,
          'subject_id',a.subject_id,
          'attestation_type',a.attestation_type,
          'verifier_type',a.verifier_type,
          'verifier_id',a.verifier_id,
          'verifier_version',a.verifier_version,
          'status',a.status,
          'assurance_level',a.assurance_level,
          'measurement_snapshot_hash',a.measurement_snapshot_hash,
          'evidence_root_hash',a.evidence_root_hash,
          'valid_from',a.valid_from,
          'valid_until',a.valid_until,
          'claims',a.claims
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
  from public.trust_attestations a
  where a.id=p_attestation_id
$$;

create or replace function public.trust_subject_identity_hash(
  p_subject_id uuid
) returns text
language sql
stable
set search_path=public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        jsonb_build_object(
          'id',s.id,
          'tenant_id',s.tenant_id,
          'subject_kind',s.subject_kind,
          'external_ref',s.external_ref,
          'provider_id',s.provider_id,
          'version',s.version,
          'identity_document',s.identity_document,
          'public_key_algorithm',s.public_key_algorithm,
          'public_key',s.public_key,
          'key_id',s.key_id
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
  from public.trust_subjects s
  where s.id=p_subject_id
$$;

create or replace function public.trust_proof_hash(
  p_subject_id uuid,
  p_state_snapshot_id uuid,
  p_attestation_id uuid,
  p_state text,
  p_assurance_level text,
  p_measurement_root_hash text,
  p_evidence_root_hash text,
  p_attestation_root_hash text,
  p_subject_identity_hash text,
  p_claims jsonb
) returns text
language sql
immutable
set search_path=public,pg_catalog
as $$
  select encode(
    extensions.digest(
      convert_to(
        jsonb_build_object(
          'proof_version','1',
          'subject_id',p_subject_id,
          'state_snapshot_id',p_state_snapshot_id,
          'attestation_id',p_attestation_id,
          'state',p_state,
          'assurance_level',p_assurance_level,
          'measurement_root_hash',p_measurement_root_hash,
          'evidence_root_hash',p_evidence_root_hash,
          'attestation_root_hash',p_attestation_root_hash,
          'subject_identity_hash',p_subject_identity_hash,
          'claims',coalesce(p_claims,'{}'::jsonb)
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
$$;

-- Creates a proof only from an existing state snapshot. This prevents an API
-- caller from manufacturing a proof for an uncomputed state.
create or replace function public.trust_create_proof(
  p_subject_id uuid,
  p_state_snapshot_id uuid,
  p_attestation_id uuid default null,
  p_claims jsonb default '{}'::jsonb
) returns public.trust_proofs
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
  s public.trust_subjects;
  ss public.trust_state_snapshots;
  a public.trust_attestations;
  p public.trust_proofs;
  mroot text;
  eroot text;
  aroot text;
  ihash text;
  phash text;
  through_time timestamptz;
begin
  if p_subject_id is null or p_state_snapshot_id is null
     or jsonb_typeof(coalesce(p_claims,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_trust_proof_request';
  end if;

  select * into s
  from public.trust_subjects
  where id=p_subject_id;

  if not found then
    raise exception 'trust_subject_not_found';
  end if;

  select * into ss
  from public.trust_state_snapshots
  where id=p_state_snapshot_id
    and subject_id=p_subject_id;

  if not found then
    raise exception 'trust_state_snapshot_not_found';
  end if;

  through_time := ss.computed_at;

  mroot := public.trust_measurement_root(p_subject_id,through_time);
  eroot := public.trust_evidence_root(p_subject_id,through_time);
  ihash := public.trust_subject_identity_hash(p_subject_id);

  if p_attestation_id is not null then
    select * into a
    from public.trust_attestations
    where id=p_attestation_id
      and subject_id=p_subject_id;

    if not found then
      raise exception 'trust_attestation_not_found';
    end if;

    if a.created_at > through_time then
      raise exception 'attestation_postdates_state_snapshot';
    end if;

    aroot := public.trust_attestation_root(a.id);

    if a.evidence_root_hash is not null
       and a.evidence_root_hash <> public.trust_attestation_evidence_root(a.id) then
      raise exception 'attestation_evidence_changed';
    end if;
  end if;

  phash := public.trust_proof_hash(
    p_subject_id,
    ss.id,
    p_attestation_id,
    ss.state,
    ss.assurance_level,
    mroot,
    eroot,
    aroot,
    ihash,
    p_claims
  );

  insert into public.trust_proofs(
    tenant_id,subject_id,state_snapshot_id,attestation_id,
    state,assurance_level,measurement_root_hash,evidence_root_hash,
    attestation_root_hash,subject_identity_hash,proof_hash,claims
  ) values (
    s.tenant_id,p_subject_id,ss.id,p_attestation_id,
    ss.state,ss.assurance_level,mroot,eroot,aroot,ihash,phash,
    coalesce(p_claims,'{}'::jsonb)
  )
  on conflict(proof_hash) do update
    set claims=public.trust_proofs.claims
  returning * into p;

  return p;
end;
$$;

revoke all on function public.trust_create_proof(uuid,uuid,uuid,jsonb)
from public,anon,authenticated;
grant execute on function public.trust_create_proof(uuid,uuid,uuid,jsonb)
to service_role;

alter table public.trust_proofs enable row level security;

drop policy if exists trust_proofs_member_read on public.trust_proofs;
create policy trust_proofs_member_read on public.trust_proofs
for select to authenticated
using (
  tenant_id is null or exists (
    select 1 from public.tenant_members tm
    where tm.tenant_id=trust_proofs.tenant_id
      and tm.user_id=auth.uid()
  )
);

revoke all on public.trust_proofs from anon;
grant select on public.trust_proofs to authenticated;

comment on table public.trust_proofs is
'Immutable deterministic Cyclothone trust provenance objects. proof_hash binds identity, state snapshot, measurements, evidence and optional attestation. It is not a certificate or signature.';

comment on function public.trust_create_proof is
'Authority-only creation of a deterministic trust proof from an existing state snapshot and real evidence. No certificate or signature is issued here.';
