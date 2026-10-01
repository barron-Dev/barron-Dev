-- Cyclothone Trust public key lifecycle hardening.
-- Applied in production as trust_public_key_lifecycle_hardening_v1.
-- Private keys remain outside PostgreSQL; this directory stores public verification keys only.

create or replace function public.trust_public_key_directory_immutable()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
    if tg_op = 'UPDATE' then
        if new.id <> old.id
           or new.key_id <> old.key_id
           or new.algorithm <> old.algorithm
           or new.purpose <> old.purpose
           or new.public_key <> old.public_key
           or new.created_at <> old.created_at then
            raise exception 'trust_public_key_directory_immutable';
        end if;
        if old.status = 'REVOKED' and new.status <> 'REVOKED' then
            raise exception 'trust_public_key_directory_revoked_terminal';
        end if;
    end if;
    return new;
end;
$$;

drop trigger if exists trust_public_key_directory_immutable on public.trust_public_key_directory;
create trigger trust_public_key_directory_immutable
before update on public.trust_public_key_directory
for each row execute function public.trust_public_key_directory_immutable();

create or replace function public.trust_register_public_key(
    p_key_id text,
    p_purpose text,
    p_public_key text,
    p_not_before timestamptz default now(),
    p_not_after timestamptz default null,
    p_metadata jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare v_id uuid; v_key bytea;
begin
    if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
    if nullif(trim(p_key_id), '') is null then raise exception 'key_id_required'; end if;
    if p_purpose not in ('TRUST_PROOF','TRUST_CERTIFICATE','TRUST_ATTESTATION','TRUST_EVIDENCE') then
        raise exception 'invalid_public_key_purpose';
    end if;
    if p_not_after is not null and p_not_after <= coalesce(p_not_before, now()) then
        raise exception 'invalid_key_validity';
    end if;
    begin
        v_key := decode(p_public_key, 'hex');
    exception when others then
        raise exception 'invalid_public_key_encoding';
    end;
    if octet_length(v_key) <> 32 then raise exception 'invalid_ed25519_public_key_length'; end if;
    insert into public.trust_public_key_directory(
        key_id, algorithm, purpose, public_key, status, not_before, not_after, metadata
    ) values (
        trim(p_key_id), 'ED25519', p_purpose, p_public_key, 'ACTIVE',
        p_not_before, p_not_after, coalesce(p_metadata, '{}'::jsonb)
    ) returning id into v_id;
    return v_id;
end;
$$;

create or replace function public.trust_revoke_public_key(p_key_id text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_count integer;
begin
    if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
    update public.trust_public_key_directory
       set status='REVOKED', revoked_at=coalesce(revoked_at, now())
     where key_id=p_key_id and status <> 'REVOKED';
    get diagnostics v_count = row_count;
    return v_count=1;
end;
$$;

revoke all on function public.trust_register_public_key(text,text,text,timestamptz,timestamptz,jsonb) from public, anon, authenticated;
grant execute on function public.trust_register_public_key(text,text,text,timestamptz,timestamptz,jsonb) to service_role;
revoke all on function public.trust_revoke_public_key(text) from public, anon, authenticated;
grant execute on function public.trust_revoke_public_key(text) to service_role;
