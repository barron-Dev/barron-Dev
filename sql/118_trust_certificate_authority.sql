-- 118_trust_certificate_authority.sql
-- Cyclothone Trust Certificate Authority.
-- Certificates are issued only from a current verified Trust State, an exact
-- state-bound Trust Proof, and a cryptographically verifiable Trust Proof
-- signature. Certificate private keys remain outside the database.

create table if not exists public.trust_certificate_profiles (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  profile_id text not null,
  version integer not null default 1 check (version > 0),
  display_name text not null,
  description text,
  required_state text not null default 'VERIFIED'
    check (required_state in ('VERIFIED')),
  required_assurance text not null default 'BASIC'
    check (required_assurance in ('NONE','BASIC','MEASURED','HARDWARE_BACKED','CRYPTOGRAPHIC')),
  max_validity_seconds integer not null default 86400
    check (max_validity_seconds between 60 and 31536000),
  required_proof_signature boolean not null default true,
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE','RETIRED')),
  created_at timestamptz not null default now(),
  unique (tenant_id,profile_id,version)
);

create index if not exists idx_trust_certificate_profiles_active
  on public.trust_certificate_profiles(tenant_id,status,profile_id);

create table if not exists public.trust_certificates (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  serial_number text not null,
  profile_id uuid not null references public.trust_certificate_profiles(id) on delete restrict,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  proof_id uuid not null references public.trust_proofs(id) on delete restrict,
  state_snapshot_id uuid not null references public.trust_state_snapshots(id) on delete restrict,
  proof_signature_id uuid not null references public.trust_proof_signatures(id) on delete restrict,
  issuer_key_id text not null,
  algorithm text not null default 'ED25519' check (algorithm='ED25519'),
  payload_version integer not null default 1 check (payload_version=1),
  payload_hash text not null check (payload_hash ~ '^[0-9a-f]{64}$'),
  signature text not null,
  claims jsonb not null default '{}'::jsonb,
  issued_at timestamptz not null default now(),
  valid_from timestamptz not null,
  valid_until timestamptz not null,
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE','EXPIRED','SUSPENDED','REVOKED')),
  revoked_at timestamptz,
  revocation_reason text,
  suspended_at timestamptz,
  suspension_reason text,
  created_at timestamptz not null default now(),
  unique (tenant_id,serial_number)
);

create unique index if not exists uq_trust_cert_active_subject_profile
  on public.trust_certificates(tenant_id,subject_id,profile_id)
  where status='ACTIVE';

create index if not exists idx_trust_certificates_subject
  on public.trust_certificates(tenant_id,subject_id,issued_at desc);

create index if not exists idx_trust_certificates_serial
  on public.trust_certificates(serial_number);

create table if not exists public.trust_certificate_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  certificate_id uuid not null references public.trust_certificates(id) on delete restrict,
  event_type text not null check (event_type in ('ISSUED','RENEWED','SUSPENDED','UNSUSPENDED','REVOKED','EXPIRED')),
  reason text,
  actor_type text not null default 'SYSTEM',
  actor_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_trust_certificate_events_cert
  on public.trust_certificate_events(certificate_id,created_at desc);

create or replace function public.trust_register_signing_key(
  p_key_id text,
  p_algorithm text,
  p_purpose text,
  p_public_key text,
  p_not_before timestamptz default now(),
  p_not_after timestamptz default null
) returns public.trust_signing_keys
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare outrow public.trust_signing_keys;
begin
  if p_algorithm <> 'ED25519' then raise exception 'unsupported_trust_algorithm'; end if;
  if p_purpose not in ('TRUST_PROOF','TRUST_CERTIFICATE') then raise exception 'invalid_trust_key_purpose'; end if;
  if p_key_id is null or length(p_key_id) < 3 or length(p_key_id) > 256 then raise exception 'invalid_trust_key_id'; end if;
  if p_public_key is null or length(p_public_key) < 32 then raise exception 'invalid_trust_public_key'; end if;
  if p_not_after is not null and p_not_after <= p_not_before then raise exception 'invalid_trust_key_validity'; end if;

  insert into public.trust_signing_keys(
    tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after
  ) values (
    null,p_key_id,p_algorithm,p_purpose,p_public_key,'ACTIVE',p_not_before,p_not_after
  )
  returning * into outrow;
  return outrow;
end $$;

revoke all on function public.trust_register_signing_key(text,text,text,text,timestamptz,timestamptz)
  from public,anon,authenticated;
grant execute on function public.trust_register_signing_key(text,text,text,text,timestamptz,timestamptz)
  to service_role;

create or replace function public.trust_issue_certificate(
  p_serial_number text,
  p_profile_id uuid,
  p_subject_id uuid,
  p_proof_id uuid,
  p_state_snapshot_id uuid,
  p_proof_signature_id uuid,
  p_issuer_key_id text,
  p_payload_hash text,
  p_signature text,
  p_claims jsonb,
  p_valid_from timestamptz,
  p_valid_until timestamptz
) returns public.trust_certificates
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare
  s public.trust_subjects;
  st public.trust_state_snapshots;
  p public.trust_proofs;
  ps public.trust_proof_signatures;
  k public.trust_signing_keys;
  prof public.trust_certificate_profiles;
  outrow public.trust_certificates;
begin
  select * into s from public.trust_subjects where id=p_subject_id;
  if not found then raise exception 'trust_subject_not_found'; end if;

  select * into st from public.trust_state_snapshots
   where id=p_state_snapshot_id and subject_id=p_subject_id;
  if not found then raise exception 'trust_state_snapshot_not_found'; end if;

  select * into p from public.trust_proofs
   where id=p_proof_id and subject_id=p_subject_id and state_snapshot_id=p_state_snapshot_id;
  if not found then raise exception 'trust_proof_binding_invalid'; end if;

  select * into ps from public.trust_proof_signatures
   where id=p_proof_signature_id and proof_id=p_proof_id and tenant_id=p.tenant_id;
  if not found then raise exception 'trust_proof_signature_not_found'; end if;

  select * into prof from public.trust_certificate_profiles
   where id=p_profile_id and (tenant_id=p.tenant_id or tenant_id is null) and status='ACTIVE';
  if not found then raise exception 'trust_certificate_profile_not_active'; end if;

  if st.state <> prof.required_state then raise exception 'trust_state_not_certifiable'; end if;
  if (
    case st.assurance_level
      when 'NONE' then 0
      when 'BASIC' then 1
      when 'MEASURED' then 2
      when 'HARDWARE_BACKED' then 3
      when 'CRYPTOGRAPHIC' then 4
      else -1
    end
  ) < (
    case prof.required_assurance
      when 'NONE' then 0
      when 'BASIC' then 1
      when 'MEASURED' then 2
      when 'HARDWARE_BACKED' then 3
      when 'CRYPTOGRAPHIC' then 4
      else 99
    end
  ) then raise exception 'trust_assurance_insufficient'; end if;

  if s.lifecycle_state <> 'ACTIVE' then raise exception 'trust_subject_not_active'; end if;
  if p.state <> st.state or p.assurance_level <> st.assurance_level then
    raise exception 'trust_proof_state_binding_invalid';
  end if;
  if ps.signed_payload_hash <> p.proof_hash then
    raise exception 'trust_proof_signature_binding_invalid';
  end if;

  select * into k from public.trust_signing_keys
   where tenant_id=p.tenant_id and key_id=p_issuer_key_id
     and purpose='TRUST_CERTIFICATE' and algorithm='ED25519'
     and status='ACTIVE' and now() >= not_before
     and (not_after is null or now() < not_after);
  if not found then raise exception 'trust_certificate_signing_key_not_active'; end if;

  if p_valid_until <= p_valid_from then raise exception 'invalid_certificate_validity'; end if;
  if p_valid_until > p_valid_from + make_interval(secs => prof.max_validity_seconds)
    then raise exception 'certificate_validity_exceeds_profile'; end if;
  if p_serial_number is null or length(p_serial_number) < 16 or length(p_serial_number) > 128
    then raise exception 'invalid_certificate_serial'; end if;
  if p_payload_hash !~ '^[0-9a-f]{64}$' then raise exception 'invalid_certificate_payload_hash'; end if;
  if p_signature is null or length(p_signature) < 32 then raise exception 'invalid_certificate_signature'; end if;

  insert into public.trust_certificates(
    tenant_id,serial_number,profile_id,subject_id,proof_id,state_snapshot_id,
    proof_signature_id,issuer_key_id,algorithm,payload_version,payload_hash,signature,
    claims,issued_at,valid_from,valid_until,status
  ) values (
    p.tenant_id,p_serial_number,p_profile_id,p_subject_id,p_proof_id,p_state_snapshot_id,
    p_proof_signature_id,p_issuer_key_id,k.algorithm,1,p_payload_hash,p_signature,
    coalesce(p_claims,'{}'::jsonb),now(),p_valid_from,p_valid_until,'ACTIVE'
  ) returning * into outrow;

  insert into public.trust_certificate_events(
    tenant_id,certificate_id,event_type,actor_type,metadata
  ) values (
    p.tenant_id,outrow.id,'ISSUED','SYSTEM',
    jsonb_build_object('profile_id',p_profile_id,'proof_id',p_proof_id)
  );
  return outrow;
end $$;

revoke all on function public.trust_issue_certificate(
  text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz
) from public,anon,authenticated;
grant execute on function public.trust_issue_certificate(
  text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz
) to service_role;

create or replace function public.trust_update_certificate_status(
  p_certificate_id uuid,
  p_status text,
  p_reason text default null
) returns public.trust_certificates
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare c public.trust_certificates; outrow public.trust_certificates;
begin
  select * into c from public.trust_certificates where id=p_certificate_id;
  if not found then raise exception 'trust_certificate_not_found'; end if;
  if p_status not in ('ACTIVE','SUSPENDED','REVOKED','EXPIRED') then raise exception 'invalid_certificate_status'; end if;
  if c.status='REVOKED' and p_status <> 'REVOKED' then raise exception 'revoked_certificate_is_terminal'; end if;

  update public.trust_certificates
    set status=p_status,
        revoked_at=case when p_status='REVOKED' then coalesce(revoked_at,now()) else revoked_at end,
        revocation_reason=case when p_status='REVOKED' then coalesce(p_reason,revocation_reason) else revocation_reason end,
        suspended_at=case when p_status='SUSPENDED' then coalesce(suspended_at,now()) else suspended_at end,
        suspension_reason=case when p_status='SUSPENDED' then coalesce(p_reason,suspension_reason) else suspension_reason end
  where id=p_certificate_id
  returning * into outrow;

  insert into public.trust_certificate_events(
    tenant_id,certificate_id,event_type,reason,actor_type
  ) values (
    outrow.tenant_id,outrow.id,
    case p_status when 'REVOKED' then 'REVOKED' when 'SUSPENDED' then 'SUSPENDED'
                 when 'ACTIVE' then 'UNSUSPENDED' else 'EXPIRED' end,
    p_reason,'SYSTEM'
  );
  return outrow;
end $$;

revoke all on function public.trust_update_certificate_status(uuid,text,text)
 from public,anon,authenticated;
grant execute on function public.trust_update_certificate_status(uuid,text,text) to service_role;

create or replace function public.trust_expire_certificates()
returns integer
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare n integer;
begin
  update public.trust_certificates
     set status='EXPIRED'
   where status='ACTIVE' and valid_until <= now();
  get diagnostics n = row_count;
  insert into public.trust_certificate_events(tenant_id,certificate_id,event_type,actor_type)
    select tenant_id,id,'EXPIRED','SYSTEM'
    from public.trust_certificates
    where status='EXPIRED' and valid_until <= now()
      and not exists (
        select 1 from public.trust_certificate_events e
        where e.certificate_id=trust_certificates.id and e.event_type='EXPIRED'
      );
  return n;
end $$;

revoke all on function public.trust_expire_certificates() from public,anon,authenticated;
grant execute on function public.trust_expire_certificates() to service_role;

alter table public.trust_certificate_profiles enable row level security;
alter table public.trust_certificates enable row level security;
alter table public.trust_certificate_events enable row level security;

drop policy if exists trust_certificate_profiles_member_read on public.trust_certificate_profiles;
create policy trust_certificate_profiles_member_read on public.trust_certificate_profiles
for select to authenticated using (
 tenant_id is null or exists (
   select 1 from public.tenant_members tm
   where tm.tenant_id=trust_certificate_profiles.tenant_id and tm.user_id=auth.uid()
 )
);

drop policy if exists trust_certificates_member_read on public.trust_certificates;
create policy trust_certificates_member_read on public.trust_certificates
for select to authenticated using (
 tenant_id is null or exists (
   select 1 from public.tenant_members tm
   where tm.tenant_id=trust_certificates.tenant_id and tm.user_id=auth.uid()
 )
);

drop policy if exists trust_certificate_events_member_read on public.trust_certificate_events;
create policy trust_certificate_events_member_read on public.trust_certificate_events
for select to authenticated using (
 tenant_id is null or exists (
   select 1 from public.tenant_members tm
   where tm.tenant_id=trust_certificate_events.tenant_id and tm.user_id=auth.uid()
 )
);

revoke all on public.trust_certificate_profiles,public.trust_certificates,public.trust_certificate_events from anon;
grant select on public.trust_certificate_profiles,public.trust_certificates,public.trust_certificate_events to authenticated;

comment on table public.trust_certificates is
'Machine-verifiable Cyclothone Trust Certificate. Issuance is gated by exact state/proof/signature bindings; cryptographic signature verification occurs at the trust service boundary before issuance.';
