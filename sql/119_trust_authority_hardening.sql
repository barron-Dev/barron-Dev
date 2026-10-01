-- 119_trust_authority_hardening.sql
-- Hardens Trust signing and certificate authority boundaries.
-- No private key material is stored in Supabase.

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
  if not exists (select 1 from public.tenants t where t.id=p_tenant_id)
    then raise exception 'trust_key_tenant_not_found'; end if;
  if p_algorithm <> 'ED25519' then raise exception 'unsupported_trust_algorithm'; end if;
  if p_purpose not in ('TRUST_PROOF','TRUST_CERTIFICATE') then raise exception 'invalid_trust_key_purpose'; end if;
  if p_key_id is null or length(p_key_id) < 3 or length(p_key_id) > 256 then raise exception 'invalid_trust_key_id'; end if;
  if p_public_key is null or length(p_public_key) < 32 or length(p_public_key) > 256 then raise exception 'invalid_trust_public_key'; end if;
  if p_not_after is not null and p_not_after <= p_not_before then raise exception 'invalid_trust_key_validity'; end if;

  insert into public.trust_signing_keys(
    tenant_id,key_id,algorithm,purpose,public_key,status,not_before,not_after
  ) values (
    p_tenant_id,p_key_id,p_algorithm,p_purpose,p_public_key,'ACTIVE',p_not_before,p_not_after
  )
  returning * into outrow;
  return outrow;
end $$;

revoke all on function public.trust_register_signing_key(
  uuid,text,text,text,text,timestamptz,timestamptz
) from public,anon,authenticated;
grant execute on function public.trust_register_signing_key(
  uuid,text,text,text,text,timestamptz,timestamptz
) to service_role;

-- The legacy 6-argument registrar could only create global/null-tenant keys.
-- Remove it so every newly registered key is tenant-bound.
revoke all on function public.trust_register_signing_key(
  text,text,text,text,timestamptz,timestamptz
) from public,anon,authenticated;
drop function if exists public.trust_register_signing_key(
  text,text,text,text,timestamptz,timestamptz
);

-- Reassert tenant binding and certificate-chain invariants.
create or replace function public.trust_sign_proof(
  p_proof_id uuid,
  p_key_id text,
  p_signature text
) returns public.trust_proof_signatures
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare
  p public.trust_proofs;
  k public.trust_signing_keys;
  outrow public.trust_proof_signatures;
begin
  select * into p from public.trust_proofs where id=p_proof_id;
  if not found then raise exception 'trust_proof_not_found'; end if;

  select * into k from public.trust_signing_keys
   where tenant_id=p.tenant_id
     and key_id=p_key_id
     and purpose='TRUST_PROOF'
     and algorithm='ED25519'
     and status='ACTIVE'
     and now() >= not_before
     and (not_after is null or now() < not_after);

  if not found then raise exception 'trust_signing_key_not_active'; end if;
  if p_signature is null or length(p_signature) < 32 then
    raise exception 'invalid_trust_signature';
  end if;

  insert into public.trust_proof_signatures(
    tenant_id,proof_id,key_id,algorithm,signature,signed_payload_hash
  ) values(
    p.tenant_id,p.id,k.key_id,k.algorithm,p_signature,p.proof_hash
  ) on conflict(proof_id,key_id,signed_payload_hash) do nothing
  returning * into outrow;

  if outrow.id is null then
    select * into outrow from public.trust_proof_signatures
    where proof_id=p.id and key_id=k.key_id and signed_payload_hash=p.proof_hash
    limit 1;
  end if;
  return outrow;
end $$;

-- Certificates are immutable after issuance. Lifecycle changes happen only
-- through the status RPC, with an append-only event.
create or replace function public.trust_certificate_immutable()
returns trigger language plpgsql set search_path=public,pg_catalog as $$
begin
  if old.id <> new.id
     or old.tenant_id is distinct from new.tenant_id
     or old.serial_number <> new.serial_number
     or old.profile_id <> new.profile_id
     or old.subject_id <> new.subject_id
     or old.proof_id <> new.proof_id
     or old.state_snapshot_id <> new.state_snapshot_id
     or old.proof_signature_id <> new.proof_signature_id
     or old.issuer_key_id <> new.issuer_key_id
     or old.algorithm <> new.algorithm
     or old.payload_version <> new.payload_version
     or old.payload_hash <> new.payload_hash
     or old.signature <> new.signature
     or old.claims is distinct from new.claims
     or old.issued_at <> new.issued_at
     or old.valid_from <> new.valid_from
     or old.valid_until <> new.valid_until
  then
    raise exception 'trust_certificate_immutable';
  end if;
  return new;
end $$;

drop trigger if exists trust_certificates_no_mutation on public.trust_certificates;
create trigger trust_certificates_no_mutation
before update on public.trust_certificates
for each row execute function public.trust_certificate_immutable();

-- Status transitions are explicit and terminal for REVOKED.
create or replace function public.trust_update_certificate_status(
  p_certificate_id uuid,
  p_status text,
  p_reason text default null
) returns public.trust_certificates
language plpgsql security definer
set search_path=public,pg_catalog
as $$
declare
  c public.trust_certificates;
  outrow public.trust_certificates;
  event_name text;
begin
  select * into c from public.trust_certificates where id=p_certificate_id;
  if not found then raise exception 'trust_certificate_not_found'; end if;
  if p_status not in ('ACTIVE','SUSPENDED','REVOKED','EXPIRED')
    then raise exception 'invalid_certificate_status'; end if;
  if c.status='REVOKED' and p_status <> 'REVOKED'
    then raise exception 'revoked_certificate_is_terminal'; end if;
  if c.status='EXPIRED' and p_status='ACTIVE'
    then raise exception 'expired_certificate_requires_reissue'; end if;

  update public.trust_certificates
    set status=p_status,
        revoked_at=case when p_status='REVOKED' then coalesce(revoked_at,now()) else revoked_at end,
        revocation_reason=case when p_status='REVOKED' then coalesce(p_reason,revocation_reason) else revocation_reason end,
        suspended_at=case when p_status='SUSPENDED' then coalesce(suspended_at,now()) else suspended_at end,
        suspension_reason=case when p_status='SUSPENDED' then coalesce(p_reason,suspension_reason) else suspension_reason end
  where id=p_certificate_id
  returning * into outrow;

  event_name := case
    when p_status='REVOKED' then 'REVOKED'
    when p_status='SUSPENDED' then 'SUSPENDED'
    when p_status='ACTIVE' then 'UNSUSPENDED'
    else 'EXPIRED'
  end;

  insert into public.trust_certificate_events(
    tenant_id,certificate_id,event_type,reason,actor_type
  ) values(outrow.tenant_id,outrow.id,event_name,p_reason,'SYSTEM');

  return outrow;
end $$;

-- Explicit public verification lookup by serial. It returns only a safe
-- verification surface; tenant-sensitive claims are not exposed.
create or replace function public.trust_public_certificate_lookup(
  p_serial_number text
) returns table(
  certificate_id uuid,
  tenant_id uuid,
  serial_number text,
  profile_id uuid,
  subject_id uuid,
  issuer_key_id text,
  algorithm text,
  payload_version integer,
  payload_hash text,
  signature text,
  proof_id uuid,
  state_snapshot_id uuid,
  proof_signature_id uuid,
  issued_at timestamptz,
  valid_from timestamptz,
  valid_until timestamptz,
  status text
)
language sql security definer
set search_path=public,pg_catalog
as $$
  select c.id,c.tenant_id,c.serial_number,c.profile_id,c.subject_id,
         c.issuer_key_id,c.algorithm,c.payload_version,c.payload_hash,c.signature,
         c.proof_id,c.state_snapshot_id,c.proof_signature_id,
         c.issued_at,c.valid_from,c.valid_until,c.status
    from public.trust_certificates c
   where c.serial_number=p_serial_number
   limit 1
$$;

revoke all on function public.trust_public_certificate_lookup(text)
 from public,anon,authenticated;
grant execute on function public.trust_public_certificate_lookup(text) to service_role;

comment on function public.trust_register_signing_key(uuid,text,text,text,text,timestamptz,timestamptz)
is 'Registers a tenant-bound public Trust signing key. Private key material remains outside Cyclothone.';

comment on function public.trust_public_certificate_lookup(text)
is 'Internal service lookup used by the public certificate verification boundary. Claims are intentionally excluded.';
