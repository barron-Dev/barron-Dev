-- Harden Trust signature ingestion.
-- PostgreSQL pgcrypto does not provide Ed25519 verification; mathematical verification
-- remains in the cryptographic execution layer. These functions therefore enforce the
-- correct Ed25519 domain and exact 64-byte base64 signature encoding before persistence.

create or replace function public.trust_sign_attestation(p_attestation_id uuid,p_key_id text,p_signature text,p_signed_payload_hash text)
returns public.trust_attestation_signatures
language plpgsql security definer set search_path=public,pg_catalog
as $$
declare a public.trust_attestations;k public.trust_signing_keys;row public.trust_attestation_signatures;raw bytea;
begin
 if current_user<>'service_role' then raise exception 'service_role_required'; end if;
 select * into a from public.trust_attestations where id=p_attestation_id for share;
 if not found then raise exception 'attestation_not_found'; end if;
 if a.status<>'VERIFIED' then raise exception 'attestation_not_verified'; end if;
 select * into k from public.trust_signing_keys where tenant_id=a.tenant_id and key_id=p_key_id and purpose='TRUST_ATTESTATION' and algorithm='ED25519' and status='ACTIVE' and (not_before is null or not_before<=now()) and (not_after is null or not_after>now());
 if not found then raise exception 'attestation_signing_key_not_active'; end if;
 if p_signed_payload_hash is distinct from public.trust_attestation_sign_payload_hash(a.id) then raise exception 'attestation_payload_hash_mismatch'; end if;
 begin raw:=decode(p_signature,'base64'); exception when others then raise exception 'invalid_attestation_signature'; end;
 if octet_length(raw)<>64 then raise exception 'invalid_attestation_signature'; end if;
 insert into public.trust_attestation_signatures(tenant_id,attestation_id,key_id,algorithm,signature,signed_payload_hash) values(a.tenant_id,a.id,p_key_id,'ED25519',p_signature,p_signed_payload_hash) returning * into row;
 update public.trust_attestations set signing_key_id=p_key_id,signature_algorithm='ED25519',signature=p_signature,signed_payload_hash=p_signed_payload_hash where id=a.id;
 return row;
end $$;

create or replace function public.trust_sign_proof(p_proof_id uuid,p_key_id text,p_signature text)
returns public.trust_proof_signatures
language plpgsql security definer set search_path=public,pg_catalog
as $$
declare p public.trust_proofs;k public.trust_signing_keys;outrow public.trust_proof_signatures;raw bytea;
begin
 if current_user<>'service_role' then raise exception 'service_role_required'; end if;
 select * into p from public.trust_proofs where id=p_proof_id;
 if not found then raise exception 'trust_proof_not_found'; end if;
 select * into k from public.trust_signing_keys where tenant_id=p.tenant_id and key_id=p_key_id and purpose='TRUST_PROOF' and algorithm='ED25519' and status='ACTIVE' and now()>=not_before and (not_after is null or now()<not_after);
 if not found then raise exception 'trust_signing_key_not_active'; end if;
 begin raw:=decode(p_signature,'base64'); exception when others then raise exception 'invalid_trust_signature'; end;
 if octet_length(raw)<>64 then raise exception 'invalid_trust_signature'; end if;
 insert into public.trust_proof_signatures(tenant_id,proof_id,key_id,algorithm,signature,signed_payload_hash) values(p.tenant_id,p.id,k.key_id,k.algorithm,p_signature,p.proof_hash) on conflict(proof_id,key_id,signed_payload_hash) do nothing returning * into outrow;
 if outrow.id is null then select * into outrow from public.trust_proof_signatures where proof_id=p.id and key_id=k.key_id and signed_payload_hash=p.proof_hash limit 1; end if;
 return outrow;
end $$;
