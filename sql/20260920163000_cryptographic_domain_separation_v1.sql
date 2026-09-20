-- Cryptographic domain separation for the existing signing-key registry.
-- Reuses public.signing_keys; no parallel key registry is introduced.
-- Domain values:
--   COMMAND      -> device command authorization
--   AI_ENVELOPE  -> short-lived AI execution capabilities
--   FEDERATION   -> federation signing material
--   COMPLIANCE   -> compliance/proof-adjacent signing
--
-- Trust proof/certificate/authority keys remain in the dedicated trust registry.

alter table public.signing_keys
  add column if not exists purpose text;

update public.signing_keys
   set purpose = 'COMMAND'
 where purpose is null;

alter table public.signing_keys
  alter column purpose set default 'COMMAND';

alter table public.signing_keys
  alter column purpose set not null;

alter table public.signing_keys
  drop constraint if exists signing_keys_purpose_check;

alter table public.signing_keys
  add constraint signing_keys_purpose_check
  check (purpose in ('COMMAND','AI_ENVELOPE','FEDERATION','COMPLIANCE'));

create index if not exists signing_keys_active_purpose_idx
  on public.signing_keys(purpose, active, kid);

comment on column public.signing_keys.purpose is
  'Cryptographic domain. A key is valid only for the explicitly requested domain; COMMAND, AI_ENVELOPE, FEDERATION and COMPLIANCE are independent domains.';

create or replace function public.get_signing_key(
  p_kid text,
  p_purpose text
) returns text
language plpgsql
security definer
set search_path = vault,public,pg_catalog
as $$
declare
  v_secret_id uuid;
  v_plaintext text;
begin
  if p_purpose not in ('COMMAND','AI_ENVELOPE','FEDERATION','COMPLIANCE') then
    raise exception 'invalid signing key purpose';
  end if;

  select vault_secret_id into v_secret_id
    from public.signing_keys
   where kid = p_kid
     and purpose = p_purpose
     and active = true;

  if v_secret_id is null then
    raise exception 'signing key % not found for purpose %', p_kid, p_purpose;
  end if;

  select decrypted_secret into v_plaintext
    from vault.decrypted_secrets
   where id = v_secret_id;

  if v_plaintext is null then
    raise exception 'vault secret % missing', v_secret_id;
  end if;

  return v_plaintext;
end;
$$;

create or replace function public.get_signing_public_key(
  p_kid text,
  p_purpose text
) returns text
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  v_public_pem text;
begin
  if p_purpose not in ('COMMAND','AI_ENVELOPE','FEDERATION','COMPLIANCE') then
    raise exception 'invalid signing key purpose';
  end if;

  select public_pem into v_public_pem
    from public.signing_keys
   where kid = p_kid
     and purpose = p_purpose
     and active = true;

  if v_public_pem is null or length(trim(v_public_pem)) = 0 then
    raise exception 'public signing key % not found for purpose %', p_kid, p_purpose;
  end if;

  return v_public_pem;
end;
$$;

create or replace function public.rotate_signing_key(
  p_new_kid text,
  p_new_pem text,
  p_public_pem text,
  p_purpose text
) returns void
language plpgsql
security definer
set search_path = vault,public,pg_catalog
as $$
declare
  v_secret_id uuid;
begin
  if p_purpose not in ('COMMAND','AI_ENVELOPE','FEDERATION','COMPLIANCE') then
    raise exception 'invalid signing key purpose';
  end if;
  if p_new_kid is null or length(trim(p_new_kid)) = 0 or length(p_new_kid) > 200 then
    raise exception 'invalid signing key id';
  end if;
  if p_new_pem is null or length(trim(p_new_pem)) = 0 then
    raise exception 'private signing key is required';
  end if;
  if p_public_pem is null or length(trim(p_public_pem)) = 0 then
    raise exception 'public signing key is required';
  end if;

  v_secret_id := vault.create_secret(
    p_new_pem,
    'cyclothone_signing_' || p_purpose || '_' || p_new_kid,
    'Ed25519 ' || p_purpose || ' signing key'
  );

  insert into public.signing_keys (
    kid, algorithm, vault_secret_id, public_pem, active, purpose
  ) values (
    p_new_kid, 'Ed25519', v_secret_id, p_public_pem, true, p_purpose
  );

  update public.signing_keys
     set active = false, retired_at = now()
   where purpose = p_purpose
     and active = true
     and kid <> p_new_kid;
end;
$$;

revoke all on function public.get_signing_key(text,text)
  from public,anon,authenticated;
grant execute on function public.get_signing_key(text,text) to service_role;

revoke all on function public.get_signing_public_key(text,text)
  from public,anon,authenticated;
grant execute on function public.get_signing_public_key(text,text) to service_role;

revoke all on function public.rotate_signing_key(text,text,text,text)
  from public,anon,authenticated;
grant execute on function public.rotate_signing_key(text,text,text,text) to service_role;

drop function if exists public.get_signing_key(text);
drop function if exists public.get_signing_public_key(text);
drop function if exists public.rotate_signing_key(text,text);

-- Direct table access remains service/backend-only.
revoke all on public.signing_keys from anon,authenticated;
grant select on public.signing_keys to service_role;
