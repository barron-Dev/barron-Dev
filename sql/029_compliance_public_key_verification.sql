-- Sentinel Compliance: verify signatures using the public key only.

alter table public.signing_keys
    add column if not exists public_key_pem text;

create or replace function public.get_signing_public_key(p_kid text)
returns text
language sql
security definer
set search_path = pg_catalog, public
as $$
    select public_key_pem
      from public.signing_keys
     where kid = p_kid and active = true
     limit 1;
$$;

revoke all on function public.get_signing_public_key(text) from public, anon, authenticated;
grant execute on function public.get_signing_public_key(text) to service_role;
