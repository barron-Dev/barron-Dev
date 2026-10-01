-- 119_trust_certificate_subject_issuance_preflight.sql
-- Subject-specific, read-only certificate issuance preflight.
-- This never issues a certificate and never bypasses trust_issue_certificate().
-- All returned reason codes are deterministic and non-secret.

create or replace function public.trust_certificate_issuance_preflight(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_profile_id uuid,
  p_state_snapshot_id uuid,
  p_proof_id uuid,
  p_proof_signature_id uuid,
  p_issuer_key_id text,
  p_trust_policy_id uuid,
  p_policy_evaluation_id uuid,
  p_valid_from timestamptz,
  p_valid_until timestamptz,
  p_serial_number text default null,
  p_payload_hash text default null,
  p_signature text default null,
  p_authority_key_id text default null,
  p_authority_signature text default null,
  p_authority_signed_payload_hash text default null
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  s public.trust_subjects;
  prof public.trust_certificate_profiles;
  st public.trust_state_snapshots;
  cur public.trust_current_state;
  p public.trust_proofs;
  ps public.trust_proof_signatures;
  proof_key public.trust_signing_keys;
  issuer_key public.trust_signing_keys;
  pol public.trust_policies;
  ev public.trust_policy_evaluations;
  authority_key public.trust_public_key_directory;
  active_certificate uuid;
  reasons text[] := array[]::text[];
  checks jsonb := '{}'::jsonb;
  assurance_rank integer;
  required_assurance_rank integer;
  ready boolean;
begin
  if current_user <> 'service_role' then
    raise exception 'service_role_required';
  end if;

  -- Subject is deliberately tenant-scoped. A missing or cross-tenant subject
  -- returns the same non-secret reason to avoid subject enumeration.
  select * into s
  from public.trust_subjects
  where id = p_subject_id
    and tenant_id = p_tenant_id;

  if not found then
    reasons := array_append(reasons, 'SUBJECT_NOT_ACCESSIBLE');
    checks := checks || jsonb_build_object('subject', false);
  else
    checks := checks || jsonb_build_object(
      'subject', true,
      'subject_active', s.lifecycle_state = 'ACTIVE'
    );
    if s.lifecycle_state <> 'ACTIVE' then
      reasons := array_append(reasons, 'SUBJECT_NOT_ACTIVE');
    end if;
  end if;

  select * into prof
  from public.trust_certificate_profiles
  where id = p_profile_id
    and status = 'ACTIVE'
    and (tenant_id = p_tenant_id or tenant_id is null);

  if not found then
    reasons := array_append(reasons, 'PROFILE_NOT_ACTIVE_OR_NOT_ACCESSIBLE');
    checks := checks || jsonb_build_object('certificate_profile', false);
  else
    checks := checks || jsonb_build_object('certificate_profile', true);
  end if;

  if s.id is not null then
    select * into st
    from public.trust_state_snapshots
    where id = p_state_snapshot_id
      and subject_id = p_subject_id
      and tenant_id = p_tenant_id;

    if not found then
      reasons := array_append(reasons, 'STATE_SNAPSHOT_NOT_FOUND');
      checks := checks || jsonb_build_object('state_snapshot', false);
    else
      checks := checks || jsonb_build_object('state_snapshot', true);

      select * into cur
      from public.trust_current_state
      where subject_id = p_subject_id
        and tenant_id = p_tenant_id;

      if not found then
        reasons := array_append(reasons, 'CURRENT_TRUST_STATE_NOT_FOUND');
        checks := checks || jsonb_build_object('current_trust_state', false);
      elsif cur.state_hash is distinct from st.state_hash
         or cur.state is distinct from st.state
         or cur.assurance_level is distinct from st.assurance_level then
        reasons := array_append(reasons, 'STATE_SNAPSHOT_NOT_CURRENT');
        checks := checks || jsonb_build_object('current_trust_state', false);
      else
        checks := checks || jsonb_build_object('current_trust_state', true);
      end if;

      if prof.id is not null and st.state <> prof.required_state then
        reasons := array_append(reasons, 'TRUST_STATE_NOT_CERTIFIABLE');
      end if;

      assurance_rank := case st.assurance_level
        when 'NONE' then 0
        when 'BASIC' then 1
        when 'MEASURED' then 2
        when 'HARDWARE_BACKED' then 3
        when 'CRYPTOGRAPHIC' then 4
        else -1
      end;
      required_assurance_rank := case
        when prof.id is null then 99
        when prof.required_assurance = 'NONE' then 0
        when prof.required_assurance = 'BASIC' then 1
        when prof.required_assurance = 'MEASURED' then 2
        when prof.required_assurance = 'HARDWARE_BACKED' then 3
        when prof.required_assurance = 'CRYPTOGRAPHIC' then 4
        else 99
      end;

      if assurance_rank < required_assurance_rank then
        reasons := array_append(reasons, 'TRUST_ASSURANCE_INSUFFICIENT');
      end if;
    end if;
  end if;

  select * into p
  from public.trust_proofs
  where id = p_proof_id
    and subject_id = p_subject_id
    and tenant_id = p_tenant_id
    and state_snapshot_id = p_state_snapshot_id;

  if not found then
    reasons := array_append(reasons, 'TRUST_PROOF_NOT_FOUND_OR_NOT_BOUND');
    checks := checks || jsonb_build_object('proof', false);
  else
    checks := checks || jsonb_build_object('proof', true);

    if st.id is not null and (
      p.state is distinct from st.state
      or p.assurance_level is distinct from st.assurance_level
    ) then
      reasons := array_append(reasons, 'TRUST_PROOF_STATE_BINDING_INVALID');
    end if;
  end if;

  select * into ps
  from public.trust_proof_signatures
  where id = p_proof_signature_id
    and proof_id = p_proof_id
    and tenant_id = p_tenant_id;

  if not found then
    reasons := array_append(reasons, 'TRUST_PROOF_SIGNATURE_NOT_FOUND_OR_NOT_BOUND');
    checks := checks || jsonb_build_object('proof_signature', false);
  else
    checks := checks || jsonb_build_object('proof_signature', true);

    if p.id is not null and ps.signed_payload_hash is distinct from p.proof_hash then
      reasons := array_append(reasons, 'TRUST_PROOF_SIGNATURE_BINDING_INVALID');
    end if;

    select * into proof_key
    from public.trust_signing_keys
    where tenant_id = p_tenant_id
      and key_id = ps.key_id
      and purpose = 'TRUST_PROOF'
      and algorithm = 'ED25519'
      and status = 'ACTIVE'
      and ps.created_at >= not_before
      and (not_after is null or ps.created_at < not_after);

    if not found then
      reasons := array_append(reasons, 'TRUST_PROOF_SIGNING_KEY_NOT_VALID_AT_SIGNATURE_TIME');
      checks := checks || jsonb_build_object('proof_signing_key', false);
    else
      checks := checks || jsonb_build_object('proof_signing_key', true);
    end if;
  end if;

  select * into pol
  from public.trust_policies
  where id = p_trust_policy_id
    and tenant_id = p_tenant_id
    and status = 'ACTIVE';

  if not found then
    reasons := array_append(reasons, 'TRUST_POLICY_NOT_ACTIVE_OR_NOT_FOUND');
    checks := checks || jsonb_build_object('trust_policy', false);
  else
    checks := checks || jsonb_build_object('trust_policy', true);
  end if;

  select * into ev
  from public.trust_policy_evaluations
  where id = p_policy_evaluation_id
    and policy_id = p_trust_policy_id
    and subject_id = p_subject_id
    and tenant_id = p_tenant_id;

  if not found then
    reasons := array_append(reasons, 'TRUST_POLICY_EVALUATION_NOT_FOUND_OR_NOT_BOUND');
    checks := checks || jsonb_build_object('policy_evaluation', false);
  else
    checks := checks || jsonb_build_object('policy_evaluation', true);

    if ev.decision <> 'CERTIFY' then
      reasons := array_append(reasons, 'TRUST_POLICY_DOES_NOT_CERTIFY');
    end if;

    if ev.evaluation_hash is null or ev.evaluation_hash !~ '^[0-9a-f]{64}$' then
      reasons := array_append(reasons, 'TRUST_POLICY_EVALUATION_HASH_INVALID');
    end if;

    if st.id is not null and ev.state_snapshot_id is distinct from st.id then
      reasons := array_append(reasons, 'TRUST_POLICY_EVALUATION_STATE_BINDING_INVALID');
    end if;

    if pol.id is not null and ev.evaluation_hash is not null
       and ev.evaluation_hash = '' then
      reasons := array_append(reasons, 'TRUST_POLICY_EVALUATION_INVALID');
    end if;
  end if;

  select * into issuer_key
  from public.trust_signing_keys
  where tenant_id = p_tenant_id
    and key_id = p_issuer_key_id
    and purpose = 'TRUST_CERTIFICATE'
    and algorithm = 'ED25519'
    and status = 'ACTIVE'
    and now() >= not_before
    and (not_after is null or now() < not_after);

  if not found then
    reasons := array_append(reasons, 'TRUST_CERTIFICATE_ISSUER_KEY_NOT_ACTIVE');
    checks := checks || jsonb_build_object('issuer_signing_key', false);
  else
    checks := checks || jsonb_build_object('issuer_signing_key', true);
  end if;

  if p_valid_from is null or p_valid_until is null or p_valid_until <= p_valid_from then
    reasons := array_append(reasons, 'CERTIFICATE_VALIDITY_INVALID');
    checks := checks || jsonb_build_object('validity_period', false);
  elsif prof.id is not null and p_valid_until > p_valid_from + make_interval(secs => prof.max_validity_seconds) then
    reasons := array_append(reasons, 'CERTIFICATE_VALIDITY_EXCEEDS_PROFILE');
    checks := checks || jsonb_build_object('validity_period', false);
  else
    checks := checks || jsonb_build_object('validity_period', true);
  end if;

  if p_serial_number is null or length(p_serial_number) < 16 or length(p_serial_number) > 128 then
    reasons := array_append(reasons, 'CERTIFICATE_SERIAL_INVALID');
    checks := checks || jsonb_build_object('serial', false);
  else
    checks := checks || jsonb_build_object('serial', true);
  end if;

  if p_payload_hash is null or p_payload_hash !~ '^[0-9a-f]{64}$' then
    reasons := array_append(reasons, 'CERTIFICATE_PAYLOAD_HASH_INVALID');
    checks := checks || jsonb_build_object('payload_hash', false);
  else
    checks := checks || jsonb_build_object('payload_hash', true);
  end if;

  if p_signature is null or length(p_signature) < 32 then
    reasons := array_append(reasons, 'CERTIFICATE_SIGNATURE_MISSING_OR_INVALID');
    checks := checks || jsonb_build_object('certificate_signature', false);
  else
    checks := checks || jsonb_build_object('certificate_signature', true);
  end if;

  select id into active_certificate
  from public.trust_certificates
  where tenant_id = p_tenant_id
    and subject_id = p_subject_id
    and profile_id = p_profile_id
    and status = 'ACTIVE'
  limit 1;

  if active_certificate is not null then
    reasons := array_append(reasons, 'ACTIVE_CERTIFICATE_ALREADY_EXISTS');
    checks := checks || jsonb_build_object('active_certificate_unique', false);
  else
    checks := checks || jsonb_build_object('active_certificate_unique', true);
  end if;

  if p_authority_key_id is null then
    reasons := array_append(reasons, 'AUTHORITY_KEY_MISSING');
    checks := checks || jsonb_build_object('authority_endorsement', false);
  else
    select * into authority_key
    from public.trust_public_key_directory
    where key_id = p_authority_key_id
      and algorithm = 'ED25519'
      and purpose = 'TRUST_CERTIFICATE'
      and status = 'ACTIVE'
      and (not_before is null or now() >= not_before)
      and (not_after is null or now() < not_after);

    if not found then
      reasons := array_append(reasons, 'AUTHORITY_KEY_NOT_ACTIVE');
      checks := checks || jsonb_build_object('authority_endorsement', false);
    else
      if p_authority_signature is null or p_authority_signature !~ '^[0-9a-fA-F]{128}$' then
        reasons := array_append(reasons, 'AUTHORITY_SIGNATURE_INVALID');
        checks := checks || jsonb_build_object('authority_endorsement', false);
      elsif p_authority_signed_payload_hash is null
         or p_authority_signed_payload_hash is distinct from p_payload_hash then
        reasons := array_append(reasons, 'AUTHORITY_PAYLOAD_BINDING_INVALID');
        checks := checks || jsonb_build_object('authority_endorsement', false);
      else
        checks := checks || jsonb_build_object('authority_endorsement', true);
      end if;
    end if;
  end if;

  ready := coalesce(array_length(reasons, 1), 0) = 0;

  return jsonb_build_object(
    'status', case when ready then 'READY' else 'NOT_READY' end,
    'capability', 'CERTIFICATE_ISSUANCE',
    'subject_id', p_subject_id,
    'profile_id', p_profile_id,
    'state_snapshot_id', p_state_snapshot_id,
    'proof_id', p_proof_id,
    'proof_signature_id', p_proof_signature_id,
    'policy_id', p_trust_policy_id,
    'policy_evaluation_id', p_policy_evaluation_id,
    'ready', ready,
    'checks', checks,
    'reason_codes', to_jsonb(coalesce(reasons, array[]::text[]))
  );
end
$function$;

revoke all on function public.trust_certificate_issuance_preflight(
  uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,timestamptz,timestamptz,text,text,text,text,text,text
) from public, anon, authenticated;

grant execute on function public.trust_certificate_issuance_preflight(
  uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,timestamptz,timestamptz,text,text,text,text,text,text
) to service_role;

comment on function public.trust_certificate_issuance_preflight(
  uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,timestamptz,timestamptz,text,text,text,text,text,text
) is 'Read-only subject-specific certificate issuance preflight. Returns deterministic non-secret reason codes and never issues a certificate.';
