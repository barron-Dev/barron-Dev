-- 141_trust_certificate_authority_public_material.sql
-- Adds authority endorsement and the public authority key to machine-verifiable
-- certificate material. Private signing keys never enter the database.

create or replace function public.trust_public_certificate_material(p_serial_number text)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare
 c public.trust_certificates; p public.trust_proofs; ps public.trust_proof_signatures;
 a public.trust_attestations; ck public.trust_signing_keys; pk public.trust_signing_keys;
 ak public.trust_signing_keys; cak public.trust_public_key_directory;
begin
 select * into c from public.trust_certificates where serial_number=p_serial_number limit 1;
 if not found then return null; end if;
 select * into p from public.trust_proofs where id=c.proof_id;
 select * into ps from public.trust_proof_signatures where id=c.proof_signature_id;
 select * into ck from public.trust_signing_keys where tenant_id=c.tenant_id and key_id=c.issuer_key_id and purpose='TRUST_CERTIFICATE' and algorithm='ED25519';
 if ps.id is not null then select * into pk from public.trust_signing_keys where tenant_id=c.tenant_id and key_id=ps.key_id and purpose='TRUST_PROOF' and algorithm='ED25519'; end if;
 if p.attestation_id is not null then
   select * into a from public.trust_attestations where id=p.attestation_id;
   if a.id is not null then select * into ak from public.trust_signing_keys where tenant_id=c.tenant_id and key_id=a.signing_key_id and purpose='TRUST_ATTESTATION' and algorithm='ED25519'; end if;
 end if;
 if c.authority_key_id is not null then select * into cak from public.trust_public_key_directory where key_id=c.authority_key_id; end if;
 return jsonb_build_object(
  'certificate',jsonb_build_object('id',c.id,'serial_number',c.serial_number,'algorithm',c.algorithm,'payload_version',c.payload_version,'payload_hash',c.payload_hash,'signature',c.signature,'proof_id',c.proof_id,'proof_signature_id',c.proof_signature_id,'issued_at',c.issued_at,'valid_from',c.valid_from,'valid_until',c.valid_until,'status',c.status,'authority_key_id',c.authority_key_id,'authority_signature',c.authority_signature,'authority_signed_payload_hash',c.authority_signed_payload_hash),
  'certificate_key',case when ck.id is null then null else jsonb_build_object('key_id',ck.key_id,'algorithm',ck.algorithm,'public_key',ck.public_key,'status',ck.status,'not_before',ck.not_before,'not_after',ck.not_after) end,
  'authority_key',case when cak.id is null then null else jsonb_build_object('key_id',cak.key_id,'algorithm',cak.algorithm,'purpose',cak.purpose,'public_key',cak.public_key,'status',cak.status,'not_before',cak.not_before,'not_after',cak.not_after) end,
  'proof',case when p.id is null then null else jsonb_build_object('id',p.id,'proof_hash',p.proof_hash,'attestation_id',p.attestation_id) end,
  'proof_signature',case when ps.id is null then null else jsonb_build_object('id',ps.id,'key_id',ps.key_id,'algorithm',ps.algorithm,'signature',ps.signature,'signed_payload_hash',ps.signed_payload_hash) end,
  'proof_key',case when pk.id is null then null else jsonb_build_object('key_id',pk.key_id,'algorithm',pk.algorithm,'public_key',pk.public_key,'status',pk.status,'not_before',pk.not_before,'not_after',pk.not_after) end,
  'attestation',case when a.id is null then null else jsonb_build_object('id',a.id,'status',a.status,'attestation_hash',a.attestation_hash,'signed_payload_hash',a.signed_payload_hash,'signature',a.signature,'signature_algorithm',a.signature_algorithm,'signing_key_id',a.signing_key_id,'valid_from',a.valid_from,'valid_until',a.valid_until) end,
  'attestation_key',case when ak.id is null then null else jsonb_build_object('key_id',ak.key_id,'algorithm',ak.algorithm,'public_key',ak.public_key,'status',ak.status,'not_before',ak.not_before,'not_after',ak.not_after) end
 );
end $$;

revoke all on function public.trust_public_certificate_material(text) from public,anon,authenticated;
grant execute on function public.trust_public_certificate_material(text) to service_role;
