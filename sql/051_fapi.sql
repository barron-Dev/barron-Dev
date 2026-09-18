-- sql/051_fapi.sql
-- FAPI 2.0 security metadata and consent/replay state.
create table if not exists fapi_clients (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    client_id text not null,
    client_name text not null,
    redirect_uris text[] not null default '{}',
    grant_types text[] not null default array['authorization_code'],
    response_types text[] not null default array['code'],
    scopes text[] not null default array['openid'],
    token_endpoint_auth_method text not null default 'tls_client_auth'
        check (token_endpoint_auth_method in ('tls_client_auth','self_signed_tls_client_auth','private_key_jwt')),
    require_pkce boolean not null default true,
    require_dpop boolean not null default false,
    jwks_uri text,
    mtls_subject text,
    status text not null default 'active'
        check (status in ('active','revoked')),
    created_at timestamptz not null default now(),
    unique (tenant_id, client_id)
);
alter table fapi_clients enable row level security;
drop policy if exists fapi_clients_tenant on fapi_clients;
create policy fapi_clients_tenant on fapi_clients for all to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists fapi_consents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    client_id uuid not null references fapi_clients(id) on delete cascade,
    subject_id uuid not null,
    scopes text[] not null,
    redirect_uri text not null,
    state_hash text,
    status text not null default 'active'
        check (status in ('active','revoked','expired')),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);
create index if not exists idx_fapi_consents_tenant_subject
on fapi_consents(tenant_id, subject_id, created_at desc);
alter table fapi_consents enable row level security;
drop policy if exists fapi_consents_tenant on fapi_consents;
create policy fapi_consents_tenant on fapi_consents for all to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists fapi_replays (
    tenant_id uuid not null references tenants(id) on delete cascade,
    proof_jti text not null,
    client_id text not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    primary key (tenant_id, proof_jti)
);
create index if not exists idx_fapi_replays_expiry on fapi_replays(expires_at);
alter table fapi_replays enable row level security;
drop policy if exists fapi_replays_tenant on fapi_replays;
create policy fapi_replays_tenant on fapi_replays for all to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists fapi_audit (
    id bigserial primary key,
    tenant_id uuid not null references tenants(id) on delete cascade,
    client_id text,
    subject_id uuid,
    event text not null,
    outcome text not null check (outcome in ('allow','deny')),
    reason text,
    request_hash text,
    created_at timestamptz not null default now()
);
create index if not exists idx_fapi_audit_tenant_time on fapi_audit(tenant_id, created_at desc);
alter table fapi_audit enable row level security;
drop policy if exists fapi_audit_tenant on fapi_audit;
create policy fapi_audit_tenant on fapi_audit for select to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

-- Internal write/replay RPCs are service-role only.
create or replace function fapi_claim_replay(
    p_tenant uuid, p_jti text, p_client_id text, p_expires timestamptz
) returns boolean language plpgsql security definer set search_path=public as $$
begin
    delete from fapi_replays where expires_at < now();
    insert into fapi_replays(tenant_id,proof_jti,client_id,expires_at)
    values(p_tenant,p_jti,p_client_id,p_expires)
    on conflict (tenant_id,proof_jti) do nothing;
    return found;
end; $$;
revoke all on function fapi_claim_replay(uuid,text,text,timestamptz) from public,anon,authenticated;
grant execute on function fapi_claim_replay(uuid,text,text,timestamptz) to service_role;
