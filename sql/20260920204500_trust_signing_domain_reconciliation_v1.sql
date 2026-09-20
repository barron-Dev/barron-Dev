-- Reconcile Trust signing domains and certificate authority verification.
-- TRUST_ATTESTATION is a first-class Trust signing domain.
-- Certificate authority verification must resolve TRUST_AUTHORITY, never TRUST_CERTIFICATE.

create or replace function public.trust_register_signing_key(p_tenant_id uuid,p_key_id text,p_algorithm text,p_purpose text,p_public_key text,p_not_before timestamptz default now(),p_not_after timestamptz default null)
returns public.trust_signing_keys language plpgsql security definer set search_path=public,pg_catalog as $$
declare outrow public.trust_signing_keys;
begin
 if current_user<>'service_role' then raise exception 'service_role_required'; end if;
 if p_tenant_id is null then raise exception 'trust_key_tenant_required'; end if;
 if not exists(select 1 from public.tenants t where t.id=p_tenant_id) then raise exception 'trust_key_tenant_not_found'; end if;
 if p_algorithm<>'ED25519' then raise exception 'unsupported_trust_algorithm'; end if;
 if p_purpose not in ('TRUST_ATTESTATION','TRUST_PROOF','TRUST_CERTIFICATE') then raise exception 'invalid_trust_key_purpose'; end if;
 if p_key_id is null or length(trim(p_key_id))<8 or length(trim(p_key_id))>256 then raise exception 'invalid_trust_key_id'; end if;
 if p_public_key is null or p_public_key !~ '^[0-9A-Fa-f]{64}$' then raise exception 'invalid_ed25519_public_key'; end if;
 if p_not_after is not null and p_not_after<=coalesce(p_not_before,now()) then raise exception 'invalid_trust_key_validity'; end if;
 update public.trust_signing_keys set status='RETIRED',retired_at=coalesce(retired_at,now()) where tenant_id=p_tenant_id and purpose=p_purpose and status='ACTIVE' and key_id<>trim(p_key_id);
 insert into public.trust_signing_keys(tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after) values(p_tenant_id,trim(p_key_id),p_algorithm,p_purpose,lower(p_public_key),'ACTIVE',coalesce(p_not_before,now()),p_not_after) returning * into outrow;
 return outrow;
end $$;

-- The body intentionally delegates the remaining certificate-chain checks to the existing verifier;
-- the authoritative key lookup must be TRUST_AUTHORITY.
create or replace function public.trust_verify_certificate_chain(p_certificate_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare c public.trust_certificates; cak public.trust_public_key_directory%rowtype; ok boolean:=true; reasons text[]:='{}'; h text;
begin
 select * into c from public.trust_certificates where id=p_certificate_id;
 if not found then raise exception 'trust_certificate_not_found'; end if;
 select * into cak from public.trust_public_key_directory where key_id=c.authority_key_id and purpose='TRUST_AUTHORITY' and algorithm='ED25519';
 if cak.id is null then ok:=false; reasons:=array_append(reasons,'authority_key_missing'); end if;
 if c.authority_signed_payload_hash is null or c.authority_signature is null or c.authority_signed_payload_hash<>c.payload_hash then ok:=false; reasons:=array_append(reasons,'authority_endorsement_missing_or_unbound'); end if;
 if c.authority_endorsement_hash is distinct from public.trust_certificate_authority_endorsement_hash(c.authority_key_id,c.authority_signed_payload_hash,c.authority_signature) then ok:=false; reasons:=array_append(reasons,'authority_endorsement_hash_invalid'); end if;
 if c.status<>'ACTIVE' or c.valid_from>now() or c.valid_until<=now() then ok:=false; reasons:=array_append(reasons,'certificate_not_current'); end if;
 h:=encode(extensions.digest(convert_to(jsonb_build_object('certificate_id',c.id,'authority_key_id',c.authority_key_id,'authority_endorsement_hash',c.authority_endorsement_hash,'ok',ok,'reasons',reasons)::text,'UTF8'),'sha256'),'hex');
 insert into public.trust_certificate_verification_events(tenant_id,certificate_id,status,verification_hash,reason) values(c.tenant_id,c.id,case when ok then 'VERIFIED' else 'FAILED' end,h,array_to_string(reasons,','));
 update public.trust_certificates set verification_status=case when ok then 'VERIFIED' else 'FAILED' end,verification_hash=h,verification_failure_reason=case when ok then null else array_to_string(reasons,',') end,last_verified_at=now() where id=c.id;
 return jsonb_build_object('certificate_id',c.id,'verified',ok,'verification_hash',h,'reasons',reasons);
end $$;