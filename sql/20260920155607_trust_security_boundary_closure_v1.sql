-- Cyclothone trust/security boundary closure
-- Migration version: 20260920155607
-- Closes ceremony challenge binding and removes direct client execution
-- of privileged SECURITY DEFINER RPCs.

create or replace function public.trust_activate_public_key_ceremony(
  p_ceremony_id uuid, p_public_key text, p_verification_hash text
) returns text
language plpgsql security definer
set search_path = public, pg_catalog
as $function$
declare
  c public.trust_public_key_ceremonies%rowtype;
  existing public.trust_public_key_directory%rowtype;
begin
  if current_user <> 'service_role' then raise exception 'service_role_required'; end if;
  select * into c from public.trust_public_key_ceremonies where id=p_ceremony_id for update;
  if not found then raise exception 'ceremony_not_found'; end if;
  if c.status<>'ISSUED' then raise exception 'ceremony_not_active'; end if;
  if c.expires_at<=now() then raise exception 'ceremony_expired'; end if;
  if length(p_public_key)<>64 or p_public_key !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid_ed25519_public_key'; end if;
  if length(p_verification_hash)<>64 or p_verification_hash !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid_verification_hash'; end if;
  if lower(p_verification_hash)<>lower(c.challenge_hash) then raise exception 'ceremony_challenge_mismatch'; end if;
  select * into existing from public.trust_public_key_directory where key_id=c.key_id for update;
  if existing.id is not null and existing.status='REVOKED' then
    insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,ceremony_id,metadata)
    values(c.key_id,c.purpose,'KEY_REACTIVATION_BLOCKED',p_ceremony_id,jsonb_build_object('reason','revoked_key_id_cannot_be_reused'));
    raise exception 'revoked_key_id_cannot_be_reused';
  end if;
  update public.trust_public_key_directory
  set status='RETIRED',metadata=metadata||jsonb_build_object('retired_by_ceremony',p_ceremony_id,'retired_at',now())
  where purpose=c.purpose and status='ACTIVE' and key_id<>c.key_id;
  if existing.id is null then
    insert into public.trust_public_key_directory(key_id,algorithm,purpose,public_key,status,metadata)
    values(c.key_id,'ED25519',c.purpose,lower(p_public_key),'ACTIVE',jsonb_build_object('ceremony_id',p_ceremony_id,'verification_hash',lower(p_verification_hash)));
  else
    update public.trust_public_key_directory
    set algorithm='ED25519',purpose=c.purpose,public_key=lower(p_public_key),status='ACTIVE',revoked_at=null,
        metadata=metadata||jsonb_build_object('ceremony_id',p_ceremony_id,'verification_hash',lower(p_verification_hash))
    where id=existing.id;
  end if;
  update public.trust_public_key_ceremonies set status='CONSUMED',consumed_at=now() where id=p_ceremony_id;
  insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,ceremony_id,metadata)
  values(c.key_id,c.purpose,'KEY_ACTIVATED',p_ceremony_id,jsonb_build_object('verification_hash',lower(p_verification_hash),'algorithm','ED25519'));
  return c.key_id;
end
$function$;

-- Close privileged RPC exposure. These functions remain available to the
-- backend service-role boundary and are not public/authenticated RPC APIs.
revoke all on function public.accept_organization_invitation(text) from public,anon,authenticated;
revoke all on function public.add_customer_case_activity(uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.assign_customer_case(uuid,uuid,uuid) from public,anon,authenticated;
revoke all on function public.open_customer_case(uuid,uuid,text,text) from public,anon,authenticated;
revoke all on function public.transition_customer_case(uuid,uuid,text,text) from public,anon,authenticated;
revoke all on function public.trust_attestation_sign_payload_hash(uuid) from public,anon,authenticated;
revoke all on function public.trust_block_suspended_certificate_reactivation() from public,anon,authenticated;
revoke all on function public.trust_continuous_verify_subject(uuid) from public,anon,authenticated;
revoke all on function public.trust_subject_has_content_verified_evidence(uuid,integer,text[]) from public,anon,authenticated;
revoke all on function public.trust_subject_has_verified_evidence(uuid,integer,text[]) from public,anon,authenticated;
revoke all on function public.trust_touch_policy_rules_hash() from public,anon,authenticated;
revoke all on function public.trust_activate_public_key_ceremony(uuid,text,text) from public,anon,authenticated;
revoke all on function public.trust_issue_public_key_ceremony(text,text,integer) from public,anon,authenticated;
revoke all on function public.trust_certificate_issuance_preflight(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,timestamptz,timestamptz,text,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.trust_issue_certificate(text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz,uuid,uuid,text,text,text) from public,anon,authenticated;

grant execute on function public.accept_organization_invitation(text) to service_role;
grant execute on function public.add_customer_case_activity(uuid,uuid,text) to service_role;
grant execute on function public.assign_customer_case(uuid,uuid,uuid) to service_role;
grant execute on function public.open_customer_case(uuid,uuid,text,text) to service_role;
grant execute on function public.transition_customer_case(uuid,uuid,text,text) to service_role;
grant execute on function public.trust_attestation_sign_payload_hash(uuid) to service_role;
grant execute on function public.trust_block_suspended_certificate_reactivation() to service_role;
grant execute on function public.trust_continuous_verify_subject(uuid) to service_role;
grant execute on function public.trust_subject_has_content_verified_evidence(uuid,integer,text[]) to service_role;
grant execute on function public.trust_subject_has_verified_evidence(uuid,integer,text[]) to service_role;
grant execute on function public.trust_touch_policy_rules_hash() to service_role;
grant execute on function public.trust_activate_public_key_ceremony(uuid,text,text) to service_role;
grant execute on function public.trust_issue_public_key_ceremony(text,text,integer) to service_role;
grant execute on function public.trust_certificate_issuance_preflight(uuid,uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,timestamptz,timestamptz,text,text,text,text,text,text) to service_role;
grant execute on function public.trust_issue_certificate(text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,timestamptz,timestamptz,uuid,uuid,text,text,text) to service_role;

-- The live database also enforces subject->tenant binding inside the
-- certificate issuer; that implementation is retained in the immediately
-- preceding reconciliation migration and is verified below.
