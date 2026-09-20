-- Cyclothone Trust v1
-- Certificate authority endorsement binding and public-key rotation support.
-- Private signing keys remain outside Cyclothone.

begin;

alter table public.trust_certificates
  add column if not exists authority_key_id text,
  add column if not exists authority_signature_algorithm text,
  add column if not exists authority_signature text,
  add column if not exists authority_signed_payload_hash text,
  add column if not exists authority_endorsement_hash text;

do $$ begin
  alter table public.trust_certificates add constraint trust_certificates_authority_sig_alg_chk
    check (authority_signature_algorithm is null or authority_signature_algorithm='ED25519');
exception when duplicate_object then null; end $$;

do $$ begin
  alter table public.trust_certificates add constraint trust_certificates_authority_hash_chk
    check (authority_signed_payload_hash is null or authority_signed_payload_hash ~ '^[0-9a-f]{64}$');
exception when duplicate_object then null; end $$;

create index if not exists idx_trust_certificates_authority_key
  on public.trust_certificates(authority_key_id);

create table if not exists public.trust_certificate_authority_endorsements (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid,
  certificate_id uuid not null references public.trust_certificates(id) on delete restrict,
  authority_key_id text not null,
  algorithm text not null default 'ED25519',
  signed_payload_hash text not null,
  signature text not null,
  endorsement_hash text not null,
  created_at timestamptz not null default now(),
  unique(certificate_id, authority_key_id, signed_payload_hash),
  check (algorithm='ED25519'),
  check (signed_payload_hash ~ '^[0-9a-f]{64}$'),
  check (endorsement_hash ~ '^[0-9a-f]{64}$')
);

alter table public.trust_certificate_authority_endorsements enable row level security;
revoke all on public.trust_certificate_authority_endorsements from anon, authenticated;
grant select on public.trust_certificate_authority_endorsements to authenticated;

create or replace function public.trust_certificate_authority_endorsement_hash(
  p_authority_key_id text,
  p_signed_payload_hash text,
  p_signature text
) returns text
language sql immutable
set search_path=public,pg_catalog
as $function$
  select encode(extensions.digest(
    convert_to(jsonb_build_object(
      'protocol','cyclothone-trust-v1',
      'authority_key_id',p_authority_key_id,
      'algorithm','ED25519',
      'signed_payload_hash',p_signed_payload_hash,
      'signature',p_signature
    )::text,'utf8'),'sha256'),'hex')
$function$;

-- Certificate issuance now requires a live ceremonially-activated global
-- TRUST_CERTIFICATE authority key plus an authority signature over the
-- exact certificate payload hash. The application verifies the Ed25519
-- signature before invoking this privileged RPC.
create or replace function public.trust_issue_certificate(
  p_serial_number text,p_profile_id uuid,p_subject_id uuid,p_proof_id uuid,
  p_state_snapshot_id uuid,p_proof_signature_id uuid,p_issuer_key_id text,
  p_payload_hash text,p_signature text,p_claims jsonb,p_valid_from timestamptz,
  p_valid_until timestamptz,p_trust_policy_id uuid default null,
  p_policy_evaluation_id uuid default null,p_authority_key_id text default null,
  p_authority_signature text default null,p_authority_signed_payload_hash text default null
) returns public.trust_certificates
language plpgsql security definer set search_path=public,pg_catalog
as $function$
declare
 s public.trust_subjects; st public.trust_state_snapshots; p public.trust_proofs;
 ps public.trust_proof_signatures; k public.trust_signing_keys; prof public.trust_certificate_profiles;
 pol public.trust_policies; ev public.trust_policy_evaluations; ak public.trust_public_key_directory;
 outrow public.trust_certificates; endorsement_hash text;
begin
 select * into s from public.trust_subjects where id=p_subject_id;
 if not found then raise exception 'trust_subject_not_found'; end if;
 select * into st from public.trust_state_snapshots where id=p_state_snapshot_id and subject_id=p_subject_id;
 if not found then raise exception 'trust_state_snapshot_not_found'; end if;
 select * into p from public.trust_proofs where id=p_proof_id and subject_id=p_subject_id and state_snapshot_id=p_state_snapshot_id;
 if not found then raise exception 'trust_proof_binding_invalid'; end if;
 select * into ps from public.trust_proof_signatures where id=p_proof_signature_id and proof_id=p_proof_id and tenant_id=p.tenant_id;
 if not found then raise exception 'trust_proof_signature_not_found'; end if;
 select * into prof from public.trust_certificate_profiles where id=p_profile_id and (tenant_id=p.tenant_id or tenant_id is null) and status='ACTIVE';
 if not found then raise exception 'trust_certificate_profile_not_active'; end if;
 if st.state<>prof.required_state then raise exception 'trust_state_not_certifiable'; end if;
 if s.lifecycle_state<>'ACTIVE' then raise exception 'trust_subject_not_active'; end if;
 if p.state<>st.state or p.assurance_level<>st.assurance_level then raise exception 'trust_proof_state_binding_invalid'; end if;
 if ps.signed_payload_hash<>p.proof_hash then raise exception 'trust_proof_signature_binding_invalid'; end if;
 if p_trust_policy_id is null or p_policy_evaluation_id is null then raise exception 'certificate_requires_trust_policy_binding'; end if;
 select * into pol from public.trust_policies where id=p_trust_policy_id and tenant_id=p.tenant_id and status='ACTIVE';
 if not found then raise exception 'trust_policy_not_active'; end if;
 select * into ev from public.trust_policy_evaluations where id=p_policy_evaluation_id and policy_id=pol.id and subject_id=p_subject_id and tenant_id=p.tenant_id;
 if not found or ev.decision<>'CERTIFY' then raise exception 'trust_policy_does_not_certify'; end if;
 select * into k from public.trust_signing_keys where tenant_id=p.tenant_id and key_id=p_issuer_key_id and purpose='TRUST_CERTIFICATE'
   and algorithm='ED25519' and status='ACTIVE' and now()>=not_before and (not_after is null or now()<not_after);
 if not found then raise exception 'trust_certificate_signing_key_not_active'; end if;
 if p_valid_until<=p_valid_from or p_valid_until>p_valid_from+make_interval(secs=>prof.max_validity_seconds) then raise exception 'invalid_certificate_validity'; end if;
 if p_payload_hash !~ '^[0-9a-f]{64}$' or p_signature is null or length(p_signature)<32 then raise exception 'invalid_certificate_signature'; end if;

 if p_authority_key_id is null or p_authority_signature is null or p_authority_signed_payload_hash is null then
   raise exception 'certificate_requires_authority_endorsement';
 end if;
 if p_authority_signed_payload_hash<>p_payload_hash then raise exception 'authority_payload_binding_invalid'; end if;
 select * into ak from public.trust_public_key_directory where key_id=p_authority_key_id
   and algorithm='ED25519' and purpose='TRUST_CERTIFICATE' and status='ACTIVE'
   and (not_before is null or now()>=not_before) and (not_after is null or now()<not_after);
 if not found then raise exception 'trust_authority_key_not_active'; end if;
 if length(p_authority_signature)<32 then raise exception 'invalid_authority_signature'; end if;

 endorsement_hash := public.trust_certificate_authority_endorsement_hash(
   p_authority_key_id,p_authority_signed_payload_hash,p_authority_signature
 );

 insert into public.trust_certificates(
   tenant_id,serial_number,profile_id,subject_id,proof_id,state_snapshot_id,proof_signature_id,issuer_key_id,
   algorithm,payload_version,payload_hash,signature,claims,issued_at,valid_from,valid_until,status,
   trust_policy_id,policy_evaluation_id,policy_version,policy_rules_hash,policy_evaluation_hash,
   authority_key_id,authority_signature_algorithm,authority_signature,authority_signed_payload_hash,authority_endorsement_hash
 ) values(
   p.tenant_id,p_serial_number,p_profile_id,p_subject_id,p_proof_id,p_state_snapshot_id,p_proof_signature_id,p_issuer_key_id,
   k.algorithm,1,p_payload_hash,p_signature,coalesce(p_claims,'{}'::jsonb),now(),p_valid_from,p_valid_until,'ACTIVE',
   pol.id,ev.id,pol.version,pol.rules_hash,ev.evaluation_hash,p_authority_key_id,'ED25519',p_authority_signature,
   p_authority_signed_payload_hash,endorsement_hash
 ) returning * into outrow;

 insert into public.trust_certificate_authority_endorsements(
   tenant_id,certificate_id,authority_key_id,algorithm,signed_payload_hash,signature,endorsement_hash
 ) values(p.tenant_id,outrow.id,p_authority_key_id,'ED25519',p_authority_signed_payload_hash,p_authority_signature,endorsement_hash);

 insert into public.trust_certificate_events(tenant_id,certificate_id,event_type,actor_type,metadata)
 values(p.tenant_id,outrow.id,'ISSUED','SYSTEM',jsonb_build_object(
   'profile_id',p_profile_id,'proof_id',p_proof_id,'trust_policy_id',pol.id,
   'policy_evaluation_id',ev.id,'authority_key_id',p_authority_key_id
 ));
 return outrow;
end
$function$;

drop function if exists public.trust_issue_certificate(
 text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz
);

-- Publish ACTIVE and still-valid RETIRED keys so historical certificates
-- remain independently verifiable during a signing-key rotation.
create or replace function public.trust_public_key_directory_json()
returns jsonb language sql stable set search_path=public,pg_catalog
as $function$
select jsonb_build_object('keys',coalesce(jsonb_agg(
 jsonb_build_object('key_id',key_id,'algorithm',algorithm,'purpose',purpose,'public_key',public_key,
 'status',status,'not_before',not_before,'not_after',not_after) order by key_id)
 filter(where status in ('ACTIVE','RETIRED')
   and (not_before is null or not_before<=now())
   and (not_after is null or not_after>now())), '[]'::jsonb))
from public.trust_public_key_directory
$function$;

commit;
