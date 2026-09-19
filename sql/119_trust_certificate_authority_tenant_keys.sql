-- 119_trust_certificate_authority_tenant_keys.sql
-- Correct Trust key provisioning so certificate/proof signing keys are tenant-scoped.

create or replace function public.trust_register_signing_key(
  p_tenant_id uuid,
  p_key_id text,
  p_algorithm text,
  p_purpose text,
  p_public_key text,
  p_not_before timestamptz default now(),
  p_not_after timestamptz default null
) returns public.trust_signing_keys
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare outrow public.trust_signing_keys;
begin
  if p_tenant_id is null then raise exception 'trust_key_tenant_required'; end if;
  if p_algorithm <> 'ED25519' then raise exception 'unsupported_trust_algorithm'; end if;
  if p_purpose not in ('TRUST_PROOF','TRUST_CERTIFICATE') then raise exception 'invalid_trust_key_purpose'; end if;
  if p_key_id is null or length(p_key_id) < 3 or length(p_key_id) > 256 then raise exception 'invalid_trust_key_id'; end if;
  if p_public_key is null or length(p_public_key) < 32 then raise exception 'invalid_trust_public_key'; end if;
  if p_not_after is not null and p_not_after <= p_not_before then raise exception 'invalid_trust_key_validity'; end if;

  insert into public.trust_signing_keys(
    tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after
  ) values (
    p_tenant_id,p_key_id,p_algorithm,p_purpose,p_public_key,'ACTIVE',p_not_before,p_not_after
  ) returning * into outrow;
  return outrow;
end $$;

revoke all on function public.trust_register_signing_key(text,text,text,text,timestamptz,timestamptz)
  from public,anon,authenticated;
grant execute on function public.trust_register_signing_key(uuid,text,text,text,text,timestamptz,timestamptz)
  to service_role;

comment on function public.trust_register_signing_key(uuid,text,text,text,text,timestamptz,timestamptz)
is 'Registers a tenant-scoped public Trust signing key. Private key material must remain in an external signer/KMS/HSM.';
