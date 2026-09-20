-- Cyclothone certificate tenant-binding closure.
-- Reconciles the live service-role issuer boundary with GitHub.
CREATE OR REPLACE FUNCTION public.trust_issue_certificate(p_serial_number text, p_profile_id uuid, p_subject_id uuid, p_proof_id uuid, p_state_snapshot_id uuid, p_proof_signature_id uuid, p_issuer_key_id text, p_payload_hash text, p_signature text, p_claims jsonb, p_valid_from timestamp with time zone, p_valid_until timestamp with time zone, p_trust_policy_id uuid DEFAULT NULL::uuid, p_policy_evaluation_id uuid DEFAULT NULL::uuid, p_authority_key_id text DEFAULT NULL::text, p_authority_signature text DEFAULT NULL::text, p_authority_signed_payload_hash text DEFAULT NULL::text)
 RETURNS trust_certificates
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
declare
  s public.trust_subjects;
  st public.trust_state_snapshots;
  p public.trust_proofs;
  ps public.trust_proof_signatures;
  k public.trust_signing_keys;
  prof public.trust_certificate_profiles;
  pol public.trust_policies;
  ev public.trust_policy_evaluations;
  ak public.trust_public_key_directory;
  outrow public.trust_certificates;
  endorsement_hash text;
begin
  if current_user <> 'service_role' then raise exception 'service_role_required'; end if;

  select * into s from public.trust_subjects where id=p_subject_id;
  if not found then raise exception 'trust_subject_not_found'; end if;

  select * into st from public.trust_state_snapshots
  where id=p_state_snapshot_id and subject_id=p_subject_id and tenant_id=s.tenant_id;
  if not found then raise exception 'trust_state_snapshot_not_found'; end if;

  select * into p from public.trust_proofs
  where id=p_proof_id and subject_id=p_subject_id
    and tenant_id=s.tenant_id and state_snapshot_id=p_state_snapshot_id;
  if not found then raise exception 'trust_proof_binding_invalid'; end if;

  select * into ps from public.trust_proof_signatures
  where id=p_proof_signature_id and proof_id=p_proof_id
    and tenant_id=s.tenant_id;
  if not found then raise exception 'trust_proof_signature_not_found'; end if;

  select * into prof from public.trust_certificate_profiles
  where id=p_profile_id and (tenant_id=s.tenant_id or tenant_id is null)
    and status='ACTIVE';
  if not found then raise exception 'trust_certificate_profile_not_active'; end if;

  if st.state<>prof.required_state then raise exception 'trust_state_not_certifiable'; end if;
  if s.lifecycle_state<>'ACTIVE' then raise exception 'trust_subject_not_active'; end if;
  if p.state<>st.state or p.assurance_level<>st.assurance_level
    then raise exception 'trust_proof_state_binding_invalid'; end if;
  if ps.signed_payload_hash<>p.proof_hash
    then raise exception 'trust_proof_signature_binding_invalid'; end if;

  if p_trust_policy_id is null or p_policy_evaluation_id is null
    then raise exception 'certificate_requires_trust_policy_binding'; end if;

  select * into pol from public.trust_policies
  where id=p_trust_policy_id and tenant_id=s.tenant_id and status='ACTIVE';
  if not found then raise exception 'trust_policy_not_active'; end if;

  select * into ev from public.trust_policy_evaluations
  where id=p_policy_evaluation_id and policy_id=pol.id
    and subject_id=p_subject_id and tenant_id=s.tenant_id;
  if not found then raise exception 'trust_policy_evaluation_not_found'; end if;
  if ev.decision<>'CERTIFY' then raise exception 'trust_policy_does_not_certify'; end if;
  if ev.evaluation_hash is null or ev.evaluation_hash !~ '^[0-9a-f]{64}$'
    then raise exception 'trust_policy_evaluation_unbound'; end if;

  select * into k from public.trust_signing_keys
  where tenant_id=s.tenant_id and key_id=p_issuer_key_id
    and purpose='TRUST_CERTIFICATE' and algorithm='ED25519'
    and status='ACTIVE' and now()>=not_before
    and (not_after is null or now()<not_after);
  if not found then raise exception 'trust_certificate_signing_key_not_active'; end if;

  if p_valid_until<=p_valid_from
     or p_valid_until>p_valid_from+make_interval(secs=>prof.max_validity_seconds)
    then raise exception 'invalid_certificate_validity'; end if;

  if p_serial_number is null or length(p_serial_number)<16 or length(p_serial_number)>128
    then raise exception 'invalid_certificate_serial'; end if;

  if p_payload_hash !~ '^[0-9a-f]{64}$'
     or p_signature is null or length(p_signature)<32
    then raise exception 'invalid_certificate_signature'; end if;

  if p_authority_key_id is null or p_authority_signature is null
     or p_authority_signed_payload_hash is null
    then raise exception 'certificate_authority_endorsement_required'; end if;

  select * into ak from public.trust_public_key_directory
  where key_id=p_authority_key_id and purpose='TRUST_AUTHORITY'
    and algorithm='ED25519' and status='ACTIVE'
    and (not_before is null or now()>=not_before)
    and (not_after is null or now()<not_after);
  if not found then raise exception 'trust_authority_key_not_active'; end if;

  if p_authority_signature !~ '^[0-9a-fA-F]{128}$'
     or p_authority_signed_payload_hash<>p_payload_hash
    then raise exception 'invalid_trust_authority_endorsement'; end if;

  if exists (
    select 1 from public.trust_certificates
    where tenant_id=s.tenant_id and subject_id=p_subject_id
      and profile_id=p_profile_id and status='ACTIVE'
  ) then raise exception 'active_certificate_already_exists'; end if;

  endorsement_hash := public.trust_certificate_authority_endorsement_hash(
    p_authority_key_id,p_authority_signed_payload_hash,p_authority_signature
  );

  insert into public.trust_certificates(
    tenant_id,serial_number,profile_id,subject_id,proof_id,state_snapshot_id,
    proof_signature_id,issuer_key_id,issuer_algorithm,version,payload_hash,
    signature,claims,issued_at,valid_from,valid_until,status,trust_policy_id,
    policy_evaluation_id,policy_version,policy_rules_hash,evaluation_hash,
    authority_key_id,authority_algorithm,authority_signature,
    authority_signed_payload_hash,authority_endorsement_hash
  )
  values(
    s.tenant_id,p_serial_number,p_profile_id,p_subject_id,p_proof_id,
    p_state_snapshot_id,p_proof_signature_id,p_issuer_key_id,k.algorithm,1,
    p_payload_hash,p_signature,coalesce(p_claims,'{}'::jsonb),now(),
    p_valid_from,p_valid_until,'ACTIVE',pol.id,ev.id,pol.version,
    pol.rules_hash,ev.evaluation_hash,p_authority_key_id,'ED25519',
    p_authority_signature,p_authority_signed_payload_hash,endorsement_hash
  )
  returning * into outrow;

  insert into public.trust_certificate_authority_endorsements(
    tenant_id,certificate_id,authority_key_id,algorithm,signed_payload_hash,
    signature,endorsement_hash
  )
  values(
    s.tenant_id,outrow.id,p_authority_key_id,'ED25519',
    p_authority_signed_payload_hash,p_authority_signature,endorsement_hash
  );

  insert into public.trust_certificate_events(
    tenant_id,certificate_id,event_type,actor_type,metadata
  )
  values(
    s.tenant_id,outrow.id,'ISSUED','SYSTEM',
    jsonb_build_object(
      'profile_id',p_profile_id,'proof_id',p_proof_id,
      'trust_policy_id',pol.id,'policy_evaluation_id',ev.id,
      'authority_key_id',p_authority_key_id
    )
  );

  return outrow;
end
$function$


revoke all on function public.trust_issue_certificate(text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz,uuid,uuid,text,text,text) from public,anon,authenticated;
grant execute on function public.trust_issue_certificate(text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz,uuid,uuid,text,text,text) to service_role;
