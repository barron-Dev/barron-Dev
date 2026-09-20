-- 140_trust_certificate_authority_endorsement_rotation.sql
-- Certificate issuance is bound to a ceremonially verified Cyclothone authority key.
-- Private signing keys remain outside Supabase.

alter table public.trust_certificates
  add column if not exists authority_key_id text,
  add column if not exists authority_signature text,
  add column if not exists authority_signed_payload_hash text;

create index if not exists idx_trust_certificates_authority_key
  on public.trust_certificates(authority_key_id);

create or replace function public.trust_certificate_require_authority_endorsement()
returns trigger language plpgsql set search_path=public as $$
declare k public.trust_public_key_directory%rowtype;
begin
  if new.authority_key_id is null or new.authority_signature is null or new.authority_signed_payload_hash is null then raise exception 'certificate_authority_endorsement_required'; end if;
  if new.authority_signed_payload_hash <> new.payload_hash then raise exception 'certificate_authority_payload_mismatch'; end if;
  select * into k from public.trust_public_key_directory where key_id=new.authority_key_id;
  if not found or k.algorithm<>'ED25519' or k.purpose<>'TRUST_CERTIFICATE' or k.status<>'ACTIVE'
     or (k.not_before is not null and k.not_before>new.issued_at)
     or (k.not_after is not null and k.not_after<=new.valid_until) then raise exception 'certificate_authority_key_not_valid_for_certificate'; end if;
  if length(new.authority_signature)<80 then raise exception 'invalid_certificate_authority_signature'; end if;
  return new;
end; $$;

drop trigger if exists trg_trust_certificate_require_authority_endorsement on public.trust_certificates;
create trigger trg_trust_certificate_require_authority_endorsement before insert on public.trust_certificates for each row execute function public.trust_certificate_require_authority_endorsement();

create or replace function public.trust_certificate_authority_immutable()
returns trigger language plpgsql set search_path=public as $$
begin
  if old.authority_key_id is distinct from new.authority_key_id or old.authority_signature is distinct from new.authority_signature or old.authority_signed_payload_hash is distinct from new.authority_signed_payload_hash then raise exception 'certificate_authority_endorsement_immutable'; end if;
  return new;
end; $$;

drop trigger if exists trg_trust_certificate_authority_immutable on public.trust_certificates;
create trigger trg_trust_certificate_authority_immutable before update on public.trust_certificates for each row execute function public.trust_certificate_authority_immutable();

-- Activating a new ceremonially verified key retires the previous active key for that purpose.
create or replace function public.trust_activate_public_key_ceremony(p_ceremony_id uuid,p_public_key text,p_verification_hash text)
returns text language plpgsql security definer set search_path=public as $$
declare c public.trust_public_key_ceremonies%rowtype;
begin
  if current_user<>'service_role' then raise exception 'service_role_required'; end if;
  select * into c from public.trust_public_key_ceremonies where id=p_ceremony_id for update;
  if not found then raise exception 'ceremony_not_found'; end if;
  if c.status<>'ISSUED' then raise exception 'ceremony_not_active'; end if;
  if c.expires_at<=now() then raise exception 'ceremony_expired'; end if;
  if length(p_public_key)<>64 or p_public_key !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid_ed25519_public_key'; end if;
  if length(p_verification_hash)<>64 or p_verification_hash !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid_verification_hash'; end if;
  update public.trust_public_key_directory set status='RETIRED',metadata=metadata||jsonb_build_object('retired_by_ceremony',p_ceremony_id,'retired_at',now())
    where purpose=c.purpose and status='ACTIVE' and key_id<>c.key_id;
  insert into public.trust_public_key_directory(key_id,algorithm,purpose,public_key,status,metadata)
  values(c.key_id,'ED25519',c.purpose,lower(p_public_key),'ACTIVE',jsonb_build_object('ceremony_id',p_ceremony_id,'verification_hash',p_verification_hash))
  on conflict(key_id) do update set algorithm=excluded.algorithm,purpose=excluded.purpose,public_key=excluded.public_key,status='ACTIVE',revoked_at=null,metadata=public.trust_public_key_directory.metadata||excluded.metadata;
  update public.trust_public_key_ceremonies set status='CONSUMED',consumed_at=now() where id=p_ceremony_id;
  return c.key_id;
end; $$;
revoke all on function public.trust_activate_public_key_ceremony(uuid,text,text) from public,anon,authenticated;
grant execute on function public.trust_activate_public_key_ceremony(uuid,text,text) to service_role;

create or replace function public.trust_retire_public_key(p_key_id text)
returns boolean language plpgsql security definer set search_path=public as $$
begin
  if current_user<>'service_role' then raise exception 'service_role_required'; end if;
  update public.trust_public_key_directory set status='RETIRED',metadata=metadata||jsonb_build_object('retired_at',now()) where key_id=p_key_id and status='ACTIVE';
  return found;
end; $$;
revoke all on function public.trust_retire_public_key(text) from public,anon,authenticated;
grant execute on function public.trust_retire_public_key(text) to service_role;

create or replace function public.trust_public_key_directory_json()
returns jsonb language sql stable set search_path=public as $$
select jsonb_build_object('keys',coalesce(jsonb_agg(jsonb_build_object('key_id',key_id,'algorithm',algorithm,'purpose',purpose,'public_key',public_key,'status',status,'not_before',not_before,'not_after',not_after) order by key_id) filter(where status in ('ACTIVE','RETIRED') and (not_before is null or not_before<=now()) and (not_after is null or not_after>now())),'[]'::jsonb)) from public.trust_public_key_directory;
$$;
revoke all on function public.trust_public_key_directory_json() from public,anon,authenticated;
grant execute on function public.trust_public_key_directory_json() to service_role;

create or replace function public.trust_verify_certificate_authority_binding(p_certificate_id uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
declare c public.trust_certificates%rowtype; k public.trust_public_key_directory%rowtype; reasons text[]:='{}'; v_hash text;
begin
  if current_user<>'service_role' then raise exception 'service_role_required'; end if;
  select * into c from public.trust_certificates where id=p_certificate_id;
  if not found then return jsonb_build_object('verified',false,'reasons',jsonb_build_array('certificate_not_found')); end if;
  if c.authority_key_id is null or c.authority_signature is null or c.authority_signed_payload_hash is null then reasons:=array_append(reasons,'certificate_authority_endorsement_missing');
  else
    select * into k from public.trust_public_key_directory where key_id=c.authority_key_id;
    if not found then reasons:=array_append(reasons,'certificate_authority_key_not_found');
    else
      if k.algorithm<>'ED25519' or k.purpose<>'TRUST_CERTIFICATE' then reasons:=array_append(reasons,'certificate_authority_key_invalid'); end if;
      if k.status='REVOKED' then reasons:=array_append(reasons,'certificate_authority_key_revoked'); end if;
      if k.not_before is not null and k.not_before>c.issued_at then reasons:=array_append(reasons,'certificate_authority_key_before_issuance'); end if;
      if k.not_after is not null and k.not_after<=c.valid_until then reasons:=array_append(reasons,'certificate_authority_key_before_certificate_expiry'); end if;
      if c.authority_signed_payload_hash<>c.payload_hash then reasons:=array_append(reasons,'certificate_authority_payload_mismatch'); end if;
    end if;
  end if;
  v_hash:=encode(extensions.digest(convert_to(jsonb_build_object('certificate_id',c.id,'authority_key_id',c.authority_key_id,'authority_signed_payload_hash',c.authority_signed_payload_hash,'reasons',reasons)::text,'utf8'),'sha256'),'hex');
  return jsonb_build_object('verified',array_length(reasons,1) is null,'reasons',to_jsonb(reasons),'verification_hash',v_hash,'authority_key_id',c.authority_key_id,'authority_signed_payload_hash',c.authority_signed_payload_hash);
end; $$;
revoke all on function public.trust_verify_certificate_authority_binding(uuid) from public,anon,authenticated;
grant execute on function public.trust_verify_certificate_authority_binding(uuid) to service_role;
