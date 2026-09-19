-- 130_trust_evidence_cryptographic_verification.sql
-- Recorded evidence != cryptographically verified evidence.
-- Ed25519 verification is performed by the Cyclothone trust authority; the DB
-- stores the immutable verification event and enforces signer/key binding.

alter table public.trust_signing_keys drop constraint if exists trust_signing_keys_purpose_check;
alter table public.trust_signing_keys add constraint trust_signing_keys_purpose_check
  check (purpose in ('TRUST_PROOF','TRUST_CERTIFICATE','TRUST_EVIDENCE'));

alter table public.trust_evidence
  add column if not exists verification_status text not null default 'UNVERIFIED'
    check (verification_status in ('UNVERIFIED','VERIFIED','FAILED','EXPIRED','REVOKED')),
  add column if not exists verifier_type text,
  add column if not exists verifier_id text,
  add column if not exists verifier_version text,
  add column if not exists verification_method text,
  add column if not exists verified_payload_hash text,
  add column if not exists verification_hash text,
  add column if not exists verified_at timestamptz,
  add column if not exists verification_failure_reason text;

create index if not exists idx_trust_evidence_verification
  on public.trust_evidence(tenant_id,subject_id,verification_status,collected_at desc);

create table if not exists public.trust_evidence_verification_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  evidence_id uuid not null references public.trust_evidence(id) on delete restrict,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  verification_status text not null check (verification_status in ('VERIFIED','FAILED','EXPIRED','REVOKED')),
  verifier_type text not null,
  verifier_id text not null,
  verifier_version text,
  verification_method text not null,
  signer_key_id text,
  signature_algorithm text,
  verified_payload_hash text,
  evidence_hash text not null check (evidence_hash ~ '^[0-9a-f]{64}$'),
  verification_hash text not null check (verification_hash ~ '^[0-9a-f]{64}$'),
  reason text,
  verified_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create index if not exists idx_trust_evidence_verification_events_evidence
  on public.trust_evidence_verification_events(evidence_id,created_at desc);

create or replace function public.trust_evidence_verification_events_immutable()
returns trigger language plpgsql set search_path=public,pg_catalog as $$
begin raise exception 'trust_evidence_verification_events_are_immutable'; end $$;

drop trigger if exists trust_evidence_verification_events_no_update on public.trust_evidence_verification_events;
create trigger trust_evidence_verification_events_no_update
before update or delete on public.trust_evidence_verification_events
for each row execute function public.trust_evidence_verification_events_immutable();

create or replace function public.trust_evidence_verification_hash(
  p_evidence_id uuid,p_subject_id uuid,p_evidence_hash text,p_verification_status text,
  p_verifier_type text,p_verifier_id text,p_verifier_version text,p_verification_method text,
  p_signer_key_id text,p_signature_algorithm text,p_verified_payload_hash text,
  p_verified_at timestamptz,p_reason text)
returns text language sql immutable strict set search_path=public,pg_catalog as $$
select encode(extensions.digest(convert_to(jsonb_build_object(
'evidence_id',p_evidence_id,'subject_id',p_subject_id,'evidence_hash',p_evidence_hash,
'verification_status',p_verification_status,'verifier_type',p_verifier_type,
'verifier_id',p_verifier_id,'verifier_version',p_verifier_version,
'verification_method',p_verification_method,'signer_key_id',p_signer_key_id,
'signature_algorithm',p_signature_algorithm,'verified_payload_hash',p_verified_payload_hash,
'verified_at',p_verified_at,'reason',p_reason)::text,'UTF8'),'sha256'),'hex') $$;

create or replace function public.trust_commit_evidence_verification(
  p_evidence_id uuid,p_verification_status text,p_verifier_type text,p_verifier_id text,
  p_verifier_version text,p_verification_method text,p_signer_key_id text,
  p_signature_algorithm text,p_verified_payload_hash text,p_verified_at timestamptz,p_reason text)
returns public.trust_evidence_verification_events
language plpgsql security definer set search_path=public,pg_catalog as $$
declare e public.trust_evidence;s public.trust_subjects;k public.trust_signing_keys;
h text;ev public.trust_evidence_verification_events;
begin
 if p_verification_status not in ('VERIFIED','FAILED','EXPIRED','REVOKED')
    or p_verifier_type is null or p_verifier_id is null or p_verification_method is null
 then raise exception 'invalid_evidence_verification'; end if;
 select * into e from public.trust_evidence where id=p_evidence_id for share;
 if not found then raise exception 'trust_evidence_not_found'; end if;
 select * into s from public.trust_subjects where id=e.subject_id for share;
 if not found then raise exception 'trust_subject_not_found'; end if;
 if e.tenant_id is distinct from s.tenant_id then raise exception 'trust_evidence_tenant_mismatch'; end if;

 if p_verification_status='VERIFIED' then
   if p_verified_payload_hash is null or p_verified_payload_hash<>e.evidence_hash
      then raise exception 'verified_payload_hash_mismatch'; end if;
   if e.signature_algorithm is null or e.signer_key_id is null or e.signature is null
      then raise exception 'signed_evidence_required'; end if;
   if p_signature_algorithm<>e.signature_algorithm or p_signer_key_id<>e.signer_key_id
      then raise exception 'evidence_signer_binding_mismatch'; end if;
   if p_signature_algorithm<>'ED25519' then raise exception 'unsupported_evidence_signature_algorithm'; end if;
   select * into k from public.trust_signing_keys
    where tenant_id=e.tenant_id and key_id=e.signer_key_id and purpose='TRUST_EVIDENCE'
      and status='ACTIVE' and now()>=not_before and (not_after is null or now()<not_after);
   if not found then raise exception 'trust_evidence_signing_key_not_active'; end if;
 end if;

 h:=public.trust_evidence_verification_hash(
   e.id,e.subject_id,e.evidence_hash,p_verification_status,p_verifier_type,p_verifier_id,
   p_verifier_version,p_verification_method,p_signer_key_id,p_signature_algorithm,
   p_verified_payload_hash,coalesce(p_verified_at,now()),p_reason);

 insert into public.trust_evidence_verification_events(
   tenant_id,evidence_id,subject_id,verification_status,verifier_type,verifier_id,
   verifier_version,verification_method,signer_key_id,signature_algorithm,
   verified_payload_hash,evidence_hash,verification_hash,reason,verified_at)
 values(e.tenant_id,e.id,e.subject_id,p_verification_status,p_verifier_type,p_verifier_id,
   p_verifier_version,p_verification_method,p_signer_key_id,p_signature_algorithm,
   p_verified_payload_hash,e.evidence_hash,h,p_reason,coalesce(p_verified_at,now()))
 returning * into ev;

 update public.trust_evidence set
   verification_status=p_verification_status,verifier_type=p_verifier_type,
   verifier_id=p_verifier_id,verifier_version=p_verifier_version,
   verification_method=p_verification_method,verified_payload_hash=p_verified_payload_hash,
   verification_hash=h,
   verified_at=case when p_verification_status='VERIFIED' then coalesce(p_verified_at,now()) else null end,
   verification_failure_reason=case when p_verification_status='VERIFIED' then null else p_reason end
 where id=e.id;
 return ev;
end $$;

revoke all on function public.trust_commit_evidence_verification(
 uuid,text,text,text,text,text,text,text,text,timestamptz,text)
from public,anon,authenticated;
grant execute on function public.trust_commit_evidence_verification(
 uuid,text,text,text,text,text,text,text,text,timestamptz,text) to service_role;

alter table public.trust_evidence_verification_events enable row level security;
drop policy if exists trust_evidence_verification_events_member_read on public.trust_evidence_verification_events;
create policy trust_evidence_verification_events_member_read
on public.trust_evidence_verification_events for select to authenticated using (
 tenant_id is null or exists (
  select 1 from public.tenant_members tm
  where tm.tenant_id=trust_evidence_verification_events.tenant_id and tm.user_id=auth.uid()
 ));
revoke all on public.trust_evidence_verification_events from anon;
grant select on public.trust_evidence_verification_events to authenticated;

create or replace function public.trust_subject_has_verified_evidence(
 p_subject_id uuid,p_max_age_seconds integer,p_required_types text[] default null)
returns boolean language sql stable security definer set search_path=public,pg_catalog as $$
select case when p_required_types is null or cardinality(p_required_types)=0 then
 exists(select 1 from public.trust_evidence e where e.subject_id=p_subject_id
  and e.verification_status='VERIFIED'
  and e.collected_at>=now()-make_interval(secs=>p_max_age_seconds)
  and (e.expires_at is null or e.expires_at>now()))
else not exists(select 1 from unnest(p_required_types) t(type) where not exists(
 select 1 from public.trust_evidence e where e.subject_id=p_subject_id
  and e.evidence_type=t.type and e.verification_status='VERIFIED'
  and e.collected_at>=now()-make_interval(secs=>p_max_age_seconds)
  and (e.expires_at is null or e.expires_at>now()))) end $$;

-- The canonical policy and execution evaluators consume the helper above.
-- A production policy can set rules.require_verified_evidence=true, while
-- component_requirements.<KIND>.require_verified_evidence can override it.
-- Trust state computation also uses verification_status, so a recorded but
-- unverified evidence object cannot silently support VERIFIED state.
