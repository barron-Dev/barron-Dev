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

 
-- Hardened state/evaluation consumers. These definitions are part of this
-- migration so a fresh environment receives the same trust semantics.
create or replace function public.trust_compute_state(p_subject_id uuid)
returns public.trust_current_state
language plpgsql security definer set search_path=public,pg_catalog as $$
declare
 s public.trust_subjects; r public.trust_current_state;
 m_count int; m_valid int; e_count int; e_valid int; e_verified int; a_count int;
 latest_m timestamptz; latest_e timestamptz; latest_a timestamptz;
 new_state text; assurance text; reason text; digest text;
begin
 select * into s from public.trust_subjects where id=p_subject_id;
 if not found then raise exception 'trust_subject_not_found'; end if;
 select count(*)::int,count(*) filter(where collected_at<=now() and(expires_at is null or expires_at>now()))::int,max(collected_at)
 into m_count,m_valid,latest_m from public.trust_measurements where subject_id=p_subject_id;
 select count(*)::int,count(*) filter(where collected_at<=now() and(expires_at is null or expires_at>now()))::int,
 count(*) filter(where verification_status='VERIFIED' and collected_at<=now() and(expires_at is null or expires_at>now()))::int,max(collected_at)
 into e_count,e_valid,e_verified,latest_e from public.trust_evidence where subject_id=p_subject_id;
 select count(*) filter(where status='VERIFIED' and(valid_until is null or valid_until>now()))::int,max(verified_at)
 into a_count,latest_a from public.trust_attestations where subject_id=p_subject_id;
 if s.lifecycle_state='REVOKED' then new_state:='REVOKED';assurance:='NONE';reason:='subject_revoked';
 elsif s.lifecycle_state='EXPIRED' then new_state:='EXPIRED';assurance:='NONE';reason:='subject_expired';
 elsif s.lifecycle_state='SUSPENDED' then new_state:='SUSPENDED';assurance:='NONE';reason:='subject_suspended';
 elsif a_count>0 and m_valid>0 and e_verified>0 then
   new_state:='VERIFIED';
   select coalesce(max(assurance_level),'BASIC') into assurance from public.trust_attestations
   where subject_id=p_subject_id and status='VERIFIED' and(valid_until is null or valid_until>now());
   reason:='verified_attestation_and_cryptographically_verified_evidence_current';
 elsif exists(select 1 from public.trust_attestations where subject_id=p_subject_id and status='VERIFIED')
       and(m_valid=0 or e_verified=0) then
   new_state:='DEGRADED';assurance:='NONE';reason:='verified_attestation_lacks_current_verified_evidence';
 elsif exists(select 1 from public.trust_attestations where subject_id=p_subject_id)
       then new_state:='ATTESTED';assurance:='BASIC';reason:='attestation_exists_but_is_not_currently_verified';
 elsif e_verified>0 then new_state:='OBSERVED';assurance:='MEASURED';reason:='cryptographically_verified_evidence_observed';
 elsif e_valid>0 then new_state:='OBSERVED';assurance:='BASIC';reason:='recorded_evidence_observed_but_not_cryptographically_verified';
 elsif m_valid>0 then new_state:='OBSERVED';assurance:='MEASURED';reason:='current_measurements_observed';
 elsif m_count>0 or e_count>0 then new_state:='DEGRADED';assurance:='NONE';reason:='only_stale_measurements_or_evidence_available';
 else new_state:='REGISTERED';assurance:='NONE';reason:='registered_without_current_evidence'; end if;
 digest:=encode(extensions.digest(convert_to(jsonb_build_object(
 'subject_id',p_subject_id,'state',new_state,'assurance_level',assurance,'measurement_count',m_count,
 'valid_measurement_count',m_valid,'evidence_count',e_count,'valid_evidence_count',e_valid,
 'verified_evidence_count',e_verified,'verified_attestation_count',a_count,'latest_measurement_at',latest_m,
 'latest_evidence_at',latest_e,'latest_attestation_at',latest_a,'reason',reason)::text,'UTF8'),'sha256'),'hex');
 insert into public.trust_state_snapshots(tenant_id,subject_id,state,assurance_level,measurement_count,valid_measurement_count,
 evidence_count,valid_evidence_count,verified_attestation_count,latest_measurement_at,latest_evidence_at,latest_attestation_at,state_reason,state_hash)
 values(s.tenant_id,p_subject_id,new_state,assurance,m_count,m_valid,e_count,e_valid,a_count,latest_m,latest_e,latest_a,reason,digest);
 insert into public.trust_current_state(subject_id,tenant_id,state,assurance_level,state_hash,reason)
 values(p_subject_id,s.tenant_id,new_state,assurance,digest,reason)
 on conflict(subject_id) do update set tenant_id=excluded.tenant_id,state=excluded.state,assurance_level=excluded.assurance_level,
 state_hash=excluded.state_hash,reason=excluded.reason,computed_at=excluded.computed_at returning * into r;
 return r;
end $$;

create or replace function public.trust_evaluate_policy(p_policy_id uuid,p_subject_id uuid)
returns public.trust_policy_evaluations
language plpgsql security definer set search_path=public,pg_catalog as $$
declare
 pol public.trust_policies; ap public.trust_assurance_profiles; s public.trust_subjects; st public.trust_current_state;
 snap public.trust_state_snapshots; outrow public.trust_policy_evaluations;
 latest_evidence timestamptz; latest_attestation timestamptz; required_ok boolean:=true; measurement_ok boolean:=false;
 evidence_fresh boolean:=false; attestation_fresh boolean:=false; verified_evidence_ok boolean:=true;
 reasons text[]:='{}'; decision text; req text; require_verified_evidence boolean;
begin
 select * into pol from public.trust_policies where id=p_policy_id and status='ACTIVE';
 if not found then raise exception 'trust_policy_not_active'; end if;
 select * into ap from public.trust_assurance_profiles where id=pol.assurance_profile_id and status='ACTIVE'
   and(tenant_id=pol.tenant_id or tenant_id is null);
 if not found then raise exception 'trust_assurance_profile_not_active'; end if;
 select * into s from public.trust_subjects where id=p_subject_id and tenant_id=pol.tenant_id;
 if not found then raise exception 'trust_subject_not_found'; end if;
 select * into st from public.trust_current_state where subject_id=p_subject_id;
 select * into snap from public.trust_state_snapshots where subject_id=p_subject_id order by computed_at desc limit 1;
 if cardinality(ap.allowed_subject_kinds)>0 and not(s.subject_kind=any(ap.allowed_subject_kinds))
 then reasons:=array_append(reasons,'subject_kind_not_allowed'); end if;
 latest_evidence:=(select max(e.collected_at) from public.trust_evidence e where e.subject_id=p_subject_id and(e.expires_at is null or e.expires_at>now()));
 latest_attestation:=(select max(a.verified_at) from public.trust_attestations a where a.subject_id=p_subject_id and a.status='VERIFIED'
   and a.valid_from<=now() and(a.valid_until is null or a.valid_until>now()));
 evidence_fresh:=latest_evidence is not null and latest_evidence>=now()-make_interval(secs=>ap.max_evidence_age_seconds);
 attestation_fresh:=latest_attestation is not null and latest_attestation>=now()-make_interval(secs=>ap.max_attestation_age_seconds);
 measurement_ok:=exists(select 1 from public.trust_measurements m where m.subject_id=p_subject_id and m.measured_at>=now()-make_interval(secs=>ap.max_evidence_age_seconds));
 require_verified_evidence:=coalesce((pol.rules->>'require_verified_evidence')::boolean,false);
 verified_evidence_ok:=not require_verified_evidence or public.trust_subject_has_verified_evidence(p_subject_id,ap.max_evidence_age_seconds,null);
 foreach req in array ap.required_evidence_types loop
   if not exists(select 1 from public.trust_evidence e where e.subject_id=p_subject_id and e.evidence_type=req
     and e.collected_at>=now()-make_interval(secs=>ap.max_evidence_age_seconds) and(e.expires_at is null or e.expires_at>now()))
   then required_ok:=false;reasons:=array_append(reasons,'missing_evidence:'||req); end if;
 end loop;
 if s.lifecycle_state<>'ACTIVE' then reasons:=array_append(reasons,'subject_not_active'); end if;
 if st is null then reasons:=array_append(reasons,'no_current_trust_state');
 elsif st.state in('SUSPENDED','REVOKED','EXPIRED') then reasons:=array_append(reasons,'trust_state_blocked');
 elsif public.trust_state_rank(st.state)<public.trust_state_rank(ap.min_state) then reasons:=array_append(reasons,'state_below_requirement'); end if;
 if st is null or public.trust_assurance_rank(st.assurance_level)<public.trust_assurance_rank(ap.min_assurance)
 then reasons:=array_append(reasons,'assurance_below_requirement'); end if;
 if ap.require_measurement and not measurement_ok then reasons:=array_append(reasons,'measurement_missing_or_stale'); end if;
 if ap.require_verified_attestation and not attestation_fresh then reasons:=array_append(reasons,'verified_attestation_missing_or_stale'); end if;
 if not evidence_fresh then reasons:=array_append(reasons,'evidence_missing_or_stale'); end if;
 if not required_ok then reasons:=array_append(reasons,'required_evidence_incomplete'); end if;
 if not verified_evidence_ok then reasons:=array_append(reasons,'cryptographically_verified_evidence_missing'); end if;
 if cardinality(reasons)=0 then decision:=pol.decision; else decision:='DENY'; end if;
 insert into public.trust_policy_evaluations(tenant_id,policy_id,subject_id,state_snapshot_id,decision,assurance,evidence_fresh,attestation_fresh,
 measurement_present,required_evidence_present,reasons,evaluation_hash)
 values(pol.tenant_id,pol.id,s.id,snap.id,decision,coalesce(st.assurance_level,'NONE'),evidence_fresh,attestation_fresh,measurement_ok,required_ok,reasons,
 encode(extensions.digest(convert_to(jsonb_build_object('policy_id',pol.id,'policy_rules_hash',pol.rules_hash,'subject_id',s.id,
 'state',coalesce(st.state,'UNKNOWN'),'assurance',coalesce(st.assurance_level,'NONE'),'evidence_fresh',evidence_fresh,
 'attestation_fresh',attestation_fresh,'measurement',measurement_ok,'required_evidence',required_ok,
 'verified_evidence',verified_evidence_ok,'reasons',reasons)::text,'UTF8'),'sha256'),'hex')) returning * into outrow;
 return outrow;
end $$;
