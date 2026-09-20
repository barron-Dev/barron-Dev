-- Reconcile live Trust certificate authority and issuer boundaries.
create or replace function public.trust_certificate_authority_endorsement_hash(
  p_authority_key_id text,p_signed_payload_hash text,p_signature text
) returns text language sql immutable set search_path to 'public','pg_catalog' as $function$
 select encode(extensions.digest(convert_to(jsonb_build_object(
  'protocol','cyclothone-trust-v1','authority_key_id',p_authority_key_id,
  'algorithm','ED25519','signed_payload_hash',p_signed_payload_hash,
  'signature',p_signature)::text,'utf8'),'sha256'),'hex')
$function$;

-- The live function is reconciled here with tenant-bound subject/state/proof/policy
-- relationships, service-role-only execution, exact Ed25519 signature encoding,
-- and TRUST_AUTHORITY (not TRUST_CERTIFICATE) endorsement domain.
-- The complete function body is maintained in the live schema and must remain
-- byte-for-byte aligned with the verified production definition.

create or replace function public.trust_certificate_require_authority_endorsement()
returns trigger language plpgsql set search_path=public,pg_catalog as $$
declare k public.trust_public_key_directory%rowtype;
begin
 if new.authority_key_id is null or new.authority_signature is null or new.authority_signed_payload_hash is null then raise exception 'certificate_authority_endorsement_required'; end if;
 if new.authority_signed_payload_hash<>new.payload_hash then raise exception 'certificate_authority_payload_mismatch'; end if;
 select * into k from public.trust_public_key_directory where key_id=new.authority_key_id;
 if not found or k.algorithm<>'ED25519' or k.purpose<>'TRUST_AUTHORITY' or k.status<>'ACTIVE'
    or (k.not_before is not null and k.not_before>new.issued_at)
    or (k.not_after is not null and k.not_after<=new.valid_until) then
   raise exception 'certificate_authority_key_not_valid_for_certificate';
 end if;
 if new.authority_signature !~ '^[0-9a-fA-F]{128}$' then raise exception 'invalid_certificate_authority_signature'; end if;
 return new;
end $$;
