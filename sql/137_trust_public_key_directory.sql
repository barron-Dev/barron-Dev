-- Cyclothone Trust Public Key Directory v1
-- Global public verification keys only; no tenant-bound key is copied implicitly.
create table if not exists public.trust_public_key_directory (
    id uuid primary key default gen_random_uuid(),
    key_id text not null unique,
    algorithm text not null default 'ED25519',
    purpose text not null,
    public_key text not null,
    status text not null default 'ACTIVE',
    not_before timestamptz,
    not_after timestamptz,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    constraint trust_public_key_directory_algorithm_ck check (algorithm='ED25519'),
    constraint trust_public_key_directory_purpose_ck check (purpose in ('TRUST_PROOF','TRUST_CERTIFICATE','TRUST_ATTESTATION','TRUST_AUTHORITY')),
    constraint trust_public_key_directory_status_ck check (status in ('ACTIVE','RETIRED','REVOKED')),
    constraint trust_public_key_directory_key_ck check (public_key ~ '^[0-9A-Fa-f]{64}$'),
    constraint trust_public_key_directory_window_ck check (not_after is null or not_before is null or not_after>not_before)
);
create index if not exists idx_trust_public_key_directory_active on public.trust_public_key_directory(status,not_before,not_after);
alter table public.trust_public_key_directory enable row level security;
revoke all on table public.trust_public_key_directory from anon,authenticated;
grant select on table public.trust_public_key_directory to anon,authenticated;
drop policy if exists trust_public_key_directory_public_read on public.trust_public_key_directory;
create policy trust_public_key_directory_public_read on public.trust_public_key_directory for select to anon,authenticated using (status='ACTIVE' and (not_before is null or not_before<=now()) and (not_after is null or not_after>now()));

create or replace function public.trust_register_public_key(p_key_id text,p_algorithm text,p_purpose text,p_public_key text,p_not_before timestamptz default null,p_not_after timestamptz default null,p_metadata jsonb default '{}'::jsonb)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 if auth.role()<>'service_role' then raise exception 'service role required'; end if;
 if p_algorithm<>'ED25519' then raise exception 'unsupported public key algorithm'; end if;
 if p_purpose not in ('TRUST_PROOF','TRUST_CERTIFICATE','TRUST_ATTESTATION','TRUST_AUTHORITY') then raise exception 'unsupported public key purpose'; end if;
 if p_key_id is null or length(trim(p_key_id))<8 or length(trim(p_key_id))>128 then raise exception 'invalid key id'; end if;
 if p_public_key is null or p_public_key !~ '^[0-9A-Fa-f]{64}$' then raise exception 'invalid Ed25519 public key'; end if;
 if p_not_after is not null and p_not_before is not null and p_not_after<=p_not_before then raise exception 'invalid key validity window'; end if;
 insert into public.trust_public_key_directory(key_id,algorithm,purpose,public_key,not_before,not_after,metadata)
 values(trim(p_key_id),p_algorithm,p_purpose,lower(p_public_key),p_not_before,p_not_after,coalesce(p_metadata,'{}'::jsonb))
 returning id into v_id;
 return v_id;
end; $$;
revoke all on function public.trust_register_public_key(text,text,text,text,timestamptz,timestamptz,jsonb) from public,anon,authenticated;

create or replace function public.trust_revoke_public_key(p_key_id text) returns boolean
language plpgsql security definer set search_path=public as $$
begin
 if auth.role()<>'service_role' then raise exception 'service role required'; end if;
 update public.trust_public_key_directory set status='REVOKED',revoked_at=coalesce(revoked_at,now()) where key_id=p_key_id and status<>'REVOKED';
 return found;
end; $$;
revoke all on function public.trust_revoke_public_key(text) from public,anon,authenticated;

create or replace function public.trust_public_key_directory_json() returns jsonb
language sql stable security invoker set search_path=public as $$
 select jsonb_build_object('keys',coalesce(jsonb_agg(jsonb_build_object('key_id',key_id,'algorithm',algorithm,'purpose',purpose,'public_key',public_key,'status',status,'not_before',not_before,'not_after',not_after) order by key_id) filter(where status='ACTIVE' and (not_before is null or not_before<=now()) and (not_after is null or not_after>now())),'[]'::jsonb))
 from public.trust_public_key_directory;
$$;
grant execute on function public.trust_public_key_directory_json() to anon,authenticated;