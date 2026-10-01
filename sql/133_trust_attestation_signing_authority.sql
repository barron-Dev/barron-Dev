-- 133_trust_attestation_signing_authority.sql
alter table public.trust_signing_keys drop constraint if exists trust_signing_keys_purpose_check;
alter table public.trust_signing_keys add constraint trust_signing_keys_purpose_check check (purpose in ('TRUST_PROOF','TRUST_CERTIFICATE','TRUST_EVIDENCE','TRUST_ATTESTATION'));

alter table public.trust_attestations
 add column if not exists signing_key_id text,
 add column if not exists signature_algorithm text,
 add column if not exists signature text,
 add column if not exists signed_payload_hash text;

create table if not exists public.trust_attestation_signatures(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,
 attestation_id uuid not null references public.trust_attestations(id) on delete restrict,key_id text not null,
 algorithm text not null check(algorithm='ED25519'),signature text not null,
 signed_payload_hash text not null check(signed_payload_hash ~ '^[0-9a-f]{64}$'),created_at timestamptz not null default now());
create unique index if not exists uq_trust_attestation_signature on public.trust_attestation_signatures(attestation_id,key_id,signed_payload_hash);
alter table public.trust_attestation_signatures enable row level security;
revoke all on public.trust_attestation_signatures from public,anon,authenticated;grant select on public.trust_attestation_signatures to authenticated;
create policy trust_attestation_signatures_member_read on public.trust_attestation_signatures for select to authenticated using(tenant_id is null or exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_attestation_signatures.tenant_id and tm.user_id=auth.uid()));

create or replace function public.trust_attestation_sign_payload_hash(p_attestation_id uuid)
returns text language plpgsql stable security definer set search_path=public,pg_catalog as $$
declare a public.trust_attestations;
begin
 select * into a from public.trust_attestations where id=p_attestation_id;if not found then raise exception 'attestation_not_found';end if;
 return encode(extensions.digest(convert_to(jsonb_build_object('attestation_id',a.id,'tenant_id',a.tenant_id,'subject_id',a.subject_id,'attestation_type',a.attestation_type,'verifier_type',a.verifier_type,'verifier_id',a.verifier_id,'verifier_version',a.verifier_version,'status',a.status,'assurance_level',a.assurance_level,'measurement_snapshot_hash',a.measurement_snapshot_hash,'evidence_root_hash',a.evidence_root_hash,'subject_identity_hash',a.subject_identity_hash,'claims_hash',a.claims_hash,'attestation_hash',a.attestation_hash,'valid_from',a.valid_from,'valid_until',a.valid_until)::text,'UTF8'),'sha256'),'hex');
end $$;

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
revoke all on function public.trust_sign_attestation(uuid,text,text,text) from public,anon,authenticated;grant execute on function public.trust_sign_attestation(uuid,text,text,text) to service_role;
