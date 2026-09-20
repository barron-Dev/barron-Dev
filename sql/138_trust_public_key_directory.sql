-- Cyclothone Trust public key directory.
-- Applied in production as migration trust_public_key_directory_v1.
-- This artifact is intentionally declarative and contains no seed/demo keys.

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
    revoked_at timestamptz
);

alter table public.trust_public_key_directory enable row level security;

revoke all on table public.trust_public_key_directory from anon, authenticated;
grant select on table public.trust_public_key_directory to anon, authenticated;

drop policy if exists trust_public_key_directory_public_read on public.trust_public_key_directory;
create policy trust_public_key_directory_public_read
on public.trust_public_key_directory
for select
to anon, authenticated
using (
    status = 'ACTIVE'
    and (not_before is null or not_before <= now())
    and (not_after is null or not_after > now())
);

revoke insert, update, delete on public.trust_public_key_directory from anon, authenticated;
grant insert, update, delete, select on public.trust_public_key_directory to service_role;

create or replace function public.trust_public_key_directory_json()
returns jsonb
language sql
stable
set search_path = public
as $$
    select jsonb_build_object(
        'keys',
        coalesce(
            jsonb_agg(
                jsonb_build_object(
                    'key_id', key_id,
                    'algorithm', algorithm,
                    'purpose', purpose,
                    'public_key', public_key,
                    'status', status,
                    'not_before', not_before,
                    'not_after', not_after
                )
                order by key_id
            ) filter (
                where status = 'ACTIVE'
                  and (not_before is null or not_before <= now())
                  and (not_after is null or not_after > now())
            ),
            '[]'::jsonb
        )
    )
    from public.trust_public_key_directory;
$$;

revoke all on function public.trust_public_key_directory_json() from public, anon, authenticated;
grant execute on function public.trust_public_key_directory_json() to service_role;
