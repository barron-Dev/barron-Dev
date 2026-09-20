-- Cyclothone Trust v1: authority endorsement in certificate chain verification.

begin;

create or replace function public.trust_verify_certificate_chain(p_certificate_id uuid)
returns jsonb language plpgsql security definer set search_path=public,'pg_catalog'
as $function$
declare
 c public.trust_certificates; p public.trust_proofs; ps public.trust_proof_signatures;
 a public.trust_attestations; s public.trust_subjects; ev public.trust_policy_evaluations;
 pol public.trust_policies; st public.trust_state_snapshots; ak public.trust_signing_keys;
 pk public.trust_signing_keys; cak public.trust_public_key_directory;
 ok boolean:=true; reasons text[]:='{}'; h text;
begin
 select * into c from public.trust_certificates where id=p_certificate_id;
 if not found then raise exception 'trust_certificate_not_found'; end if;
 select * into s from public.trust_subjects where id=c.subject_id;
 select * into st from public.trust_state_snapshots where id=c.state_snapshot_id and subject_id=c.subject_id;
 select * into p from public.trust_proofs where id=c.proof_id and subject_id=c.subject_id and state_snapshot_id=c.state_snapshot_id;
 select * into ps from public.trust_proof_signatures where id=c.proof_signature_id and proof_id=c.proof_id;
 select * into pol from public.trust_policies where id=c.trust_policy_id and tenant_id=c.tenant_id;
 select * into ev from public.trust_policy_evaluations where id=c.policy_evaluation_id and policy_id=c.trust_policy_id and subject_id=c.subject_id and tenant_id=c.tenant_id;
 select * into ak from public.trust_signing_keys where tenant_id=c.tenant_id and key_id=c.issuer_key_id and purpose='TRUST_CERTIFICATE' and algorithm='ED25519';
 select * into cak from public.trust_public_key_directory where key_id=c.authority_key_id and purpose='TRUST_CERTIFICATE' and algorithm='ED25519';

 if s.id is null then ok:=false; reasons:=array_append(reasons,'subject_missing'); end if;
 if st.id is null then ok:=false; reasons:=array_append(reasons,'state_snapshot_missing'); end if;
 if p.id is null then ok:=false; reasons:=array_append(reasons,'proof_missing'); end if;
 if ps.id is null or ps.signed_payload_hash<>p.proof_hash then ok:=false; reasons:=array_append(reasons,'proof_signature_binding_invalid'); end if;
 if ak.id is null then ok:=false; reasons:=array_append(reasons,'certificate_signing_key_missing'); end if;
 if pol.id is null then ok:=false; reasons:=array_append(reasons,'policy_missing'); end if;
 if ev.id is null or ev.decision<>'CERTIFY' then ok:=false; reasons:=array_append(reasons,'policy_certification_invalid'); end if;
 if pol.id is not null and c.policy_rules_hash is distinct from pol.rules_hash then ok:=false; reasons:=array_append(reasons,'policy_rules_hash_mismatch'); end if;
 if ev.id is not null and c.policy_evaluation_hash is distinct from ev.evaluation_hash then ok:=false; reasons:=array_append(reasons,'policy_evaluation_hash_mismatch'); end if;

 if c.authority_key_id is null or c.authority_signature is null or c.authority_signed_payload_hash is null
    or c.authority_signed_payload_hash<>c.payload_hash
 then ok:=false; reasons:=array_append(reasons,'authority_endorsement_missing_or_unbound'); end if;
 if cak.id is null then
   ok:=false; reasons:=array_append(reasons,'authority_key_missing');
 else
   if cak.status not in ('ACTIVE','RETIRED') then ok:=false; reasons:=array_append(reasons,'authority_key_not_usable'); end if;
   if cak.not_before is not null and cak.not_before>now() then ok:=false; reasons:=array_append(reasons,'authority_key_not_yet_valid'); end if;
   if cak.not_after is not null and cak.not_after<=now() then ok:=false; reasons:=array_append(reasons,'authority_key_expired'); end if;
 end if;
 if c.authority_endorsement_hash is distinct from public.trust_certificate_authority_endorsement_hash(
   c.authority_key_id,c.authority_signed_payload_hash,c.authority_signature
 ) then ok:=false; reasons:=array_append(reasons,'authority_endorsement_hash_invalid'); end if;

 if c.status<>'ACTIVE' or c.valid_from>now() or c.valid_until<=now() then ok:=false; reasons:=array_append(reasons,'certificate_not_current'); end if;
 if s.id is not null and s.lifecycle_state<>'ACTIVE' then ok:=false; reasons:=array_append(reasons,'subject_not_active'); end if;
 if p.id is not null and p.proof_hash<>public.trust_proof_hash(
   p.subject_id,p.state_snapshot_id,p.attestation_id,p.state,p.assurance_level,
   p.measurement_root_hash,p.evidence_root_hash,p.attestation_root_hash,p.subject_identity_hash,p.claims
 ) then ok:=false; reasons:=array_append(reasons,'proof_hash_invalid'); end if;

 if p.attestation_id is not null then
   select * into a from public.trust_attestations where id=p.attestation_id and subject_id=p.subject_id;
 end if;
 if a.id is null and p.attestation_id is not null then ok:=false; reasons:=array_append(reasons,'attestation_missing'); end if;
 if a.id is not null then
   select * into pk from public.trust_signing_keys where tenant_id=a.tenant_id and key_id=a.signing_key_id and purpose='TRUST_ATTESTATION' and algorithm='ED25519';
   if a.status<>'VERIFIED' then ok:=false; reasons:=array_append(reasons,'attestation_not_verified'); end if;
   if a.attestation_hash<>public.trust_attestation_hash(a.id,a.subject_id,a.attestation_type,a.verifier_type,a.verifier_id,a.verifier_version,a.status,a.assurance_level,a.subject_identity_hash,a.measurement_snapshot_hash,a.evidence_root_hash,a.claims_hash,a.valid_from,a.valid_until,a.verification_method)
      then ok:=false; reasons:=array_append(reasons,'attestation_hash_invalid'); end if;
   if pk.id is null or a.signature is null or a.signature_algorithm<>'ED25519' or a.signed_payload_hash<>public.trust_attestation_sign_payload_hash(a.id)
      then ok:=false; reasons:=array_append(reasons,'attestation_signature_invalid'); end if;
 end if;

 if c.payload_hash !~ '^[0-9a-f]{64}$' or c.signature is null or c.algorithm<>'ED25519'
    then ok:=false; reasons:=array_append(reasons,'certificate_signature_invalid'); end if;

 h:=encode(extensions.digest(convert_to(jsonb_build_object(
   'certificate_id',c.id,'proof_id',c.proof_id,'policy_id',c.trust_policy_id,
   'policy_evaluation_id',c.policy_evaluation_id,'policy_rules_hash',c.policy_rules_hash,
   'policy_evaluation_hash',c.policy_evaluation_hash,'authority_key_id',c.authority_key_id,
   'authority_endorsement_hash',c.authority_endorsement_hash,'ok',ok,'reasons',reasons
 )::text,'UTF8'),'sha256'),'hex');

 insert into public.trust_certificate_verification_events(tenant_id,certificate_id,status,verification_hash,reason)
 values(c.tenant_id,c.id,case when ok then 'VERIFIED' else 'FAILED' end,h,array_to_string(reasons,','));
 update public.trust_certificates set verification_status=case when ok then 'VERIFIED' else 'FAILED' end,
 verification_hash=h,verification_failure_reason=case when ok then null else array_to_string(reasons,',') end,
 last_verified_at=now() where id=c.id;
 return jsonb_build_object('certificate_id',c.id,'verified',ok,'verification_hash',h,'reasons',reasons);
end
$function$;

commit;
