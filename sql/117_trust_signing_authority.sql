-- 117_trust_signing_authority.sql
-- Dedicated Trust signing domain. Trust keys are never interchangeable with
-- device, command, federation, envelope, or proof-verification identities.

create table if not exists public.trust_signing_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  key_id text not null,
  algorithm text not null check (algorithm in ('ED25519')),
  purpose text not null default 'TRUST_PROOF'
    check (purpose in ('TRUST_PROOF','TRUST_CERTIFICATE')),
  public_key text not null,
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE','RETIRED','REVOKED')),
  not_before timestamptz not null default now(),
  not_after timestamptz,
  created_at timestamptz not null default now(),
  retired_at timestamptz,
  revoked_at timestamptz,
  unique (tenant_id,key_id)
);

create index if not exists idx_trust_signing_keys_active
 on public.trust_signing_keys(tenant_id,status,purpose);

create table if not exists public.trust_proof_signatures (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  proof_id uuid not null references public.trust_proofs(id) on delete restrict,
  key_id text not null,
  algorithm text not null check (algorithm in ('ED25519')),
  signature text not null,
  signed_payload_hash text not null check (signed_payload_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  unique(proof_id,key_id,signed_payload_hash)
);

create index if not exists idx_trust_proof_signatures_proof
 on public.trust_proof_signatures(proof_id,created_at desc);

-- Trust proof signatures are append-only. Revocation/rotation happens at key level.
create or replace function public.trust_proof_signatures_immutable()
returns trigger language plpgsql set search_path=public,pg_catalog as $$
begin
  raise exception 'trust_proof_signatures_are_immutable';
end $$;

drop trigger if exists trust_proof_signatures_no_update on public.trust_proof_signatures;
create trigger trust_proof_signatures_no_update
before update or delete on public.trust_proof_signatures
for each row execute function public.trust_proof_signatures_immutable();

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

 select * into k
 from public.trust_signing_keys
 where tenant_id=p.tenant_id
   and key_id=p_key_id
   and purpose='TRUST_PROOF'
   and status='ACTIVE'
   and now() >= not_before
   and (not_after is null or now() < not_after);

 if not found then raise exception 'trust_signing_key_not_active'; end if;

 if p_signature is null or length(p_signature) < 16 then
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

revoke all on function public.trust_sign_proof(uuid,text,text)
 from public,anon,authenticated;
grant execute on function public.trust_sign_proof(uuid,text,text) to service_role;

alter table public.trust_signing_keys enable row level security;
alter table public.trust_proof_signatures enable row level security;

drop policy if exists trust_signing_keys_member_read on public.trust_signing_keys;
create policy trust_signing_keys_member_read on public.trust_signing_keys
for select to authenticated using (
 tenant_id is null or exists (
   select 1 from public.tenant_members tm
   where tm.tenant_id=trust_signing_keys.tenant_id and tm.user_id=auth.uid()
 )
);

drop policy if exists trust_proof_signatures_member_read on public.trust_proof_signatures;
create policy trust_proof_signatures_member_read on public.trust_proof_signatures
for select to authenticated using (
 tenant_id is null or exists (
   select 1 from public.tenant_members tm
   where tm.tenant_id=trust_proof_signatures.tenant_id and tm.user_id=auth.uid()
 )
);

revoke all on public.trust_signing_keys,public.trust_proof_signatures from anon;
grant select on public.trust_signing_keys,public.trust_proof_signatures to authenticated;

comment on table public.trust_signing_keys is
'Dedicated Cyclothone Trust cryptographic key domain. Private key material is intentionally never stored here.';
comment on function public.trust_sign_proof is
'Attaches an externally produced signature to a deterministic trust proof using an active TRUST_PROOF key identity. Private signing material remains outside the database.';
