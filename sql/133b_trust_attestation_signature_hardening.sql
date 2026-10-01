-- 133b_trust_attestation_signature_hardening.sql
-- Only verified attestations can be signed; key validity remains tenant-bound.
create or replace function public.trust_sign_attestation(p_attestation_id uuid,p_key_id text,p_signature text,p_signed_payload_hash text)
returns public.trust_attestation_signatures language plpgsql security definer set search_path=public,pg_catalog as $$
declare a public.trust_attestations;k public.trust_signing_keys;row public.trust_attestation_signatures;
begin
 select * into a from public.trust_attestations where id=p_attestation_id for share;if not found then raise exception 'attestation_not_found';end if;
 if a.status<>'VERIFIED' then raise exception 'attestation_not_verified';end if;
 select * into k from public.trust_signing_keys where tenant_id=a.tenant_id and key_id=p_key_id and purpose='TRUST_ATTESTATION' and algorithm='ED25519' and status='ACTIVE' and(not_before is null or not_before<=now()) and(not_after is null or not_after>now());if not found then raise exception 'attestation_signing_key_not_active';end if;
 if p_signed_payload_hash is distinct from public.trust_attestation_sign_payload_hash(a.id) then raise exception 'attestation_payload_hash_mismatch';end if;
 if p_signature is null or length(trim(p_signature))<80 then raise exception 'invalid_attestation_signature';end if;
 insert into public.trust_attestation_signatures(tenant_id,attestation_id,key_id,algorithm,signature,signed_payload_hash) values(a.tenant_id,a.id,p_key_id,'ED25519',p_signature,p_signed_payload_hash) returning * into row;
 update public.trust_attestations set signing_key_id=p_key_id,signature_algorithm='ED25519',signature=p_signature,signed_payload_hash=p_signed_payload_hash where id=a.id;
 return row;
end $$;