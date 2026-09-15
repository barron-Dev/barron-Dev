-- Sentinel Developer Platform, migration 016.
-- Secrets are hashed at rest. OAuth tokens are opaque and server-managed.

create table if not exists developers (
    user_id uuid primary key references auth.users(id) on delete cascade,
    tenant_id uuid not null references tenants(id) on delete cascade,
    created_at timestamptz not null default now()
);
create index if not exists idx_developers_tenant on developers(tenant_id);

create table if not exists developer_apps (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
    owner_user_id uuid not null references auth.users(id) on delete restrict,
    name text not null check (length(name) between 1 and 120), description text,
    active boolean not null default true, allowed_scopes text[] not null default '{}', redirect_uris text[] not null default '{}',
    created_at timestamptz not null default now(), updated_at timestamptz not null default now(), unique(tenant_id,name)
);
create index if not exists idx_developer_apps_owner on developer_apps(owner_user_id);

create table if not exists oauth_clients (
    id uuid primary key default gen_random_uuid(), app_id uuid not null references developer_apps(id) on delete cascade,
    client_id text not null unique, client_secret_hash text, public_client boolean not null default false,
    active boolean not null default true, created_at timestamptz not null default now(), last_used_at timestamptz
);
create table if not exists oauth_authorization_codes (
    id uuid primary key default gen_random_uuid(), code_hash text not null unique,
    client_id uuid not null references oauth_clients(id) on delete cascade, user_id uuid not null references auth.users(id) on delete cascade,
    app_id uuid not null references developer_apps(id) on delete cascade, redirect_uri text not null,
    scope text[] not null default '{}', code_challenge text, code_challenge_method text check(code_challenge_method in ('S256','plain')),
    expires_at timestamptz not null, consumed_at timestamptz, created_at timestamptz not null default now()
);
create table if not exists oauth_access_tokens (
    id uuid primary key default gen_random_uuid(), token_hash text not null unique,
    client_id uuid not null references oauth_clients(id) on delete cascade, user_id uuid references auth.users(id) on delete cascade,
    app_id uuid not null references developer_apps(id) on delete cascade, scope text[] not null default '{}',
    expires_at timestamptz not null, revoked_at timestamptz, created_at timestamptz not null default now()
);
create index if not exists idx_oauth_access_tokens_active on oauth_access_tokens(token_hash,expires_at) where revoked_at is null;
create table if not exists oauth_refresh_tokens (
    id uuid primary key default gen_random_uuid(), token_hash text not null unique,
    client_id uuid not null references oauth_clients(id) on delete cascade, user_id uuid references auth.users(id) on delete cascade,
    app_id uuid not null references developer_apps(id) on delete cascade, scope text[] not null default '{}',
    expires_at timestamptz not null, revoked_at timestamptz, replaced_by uuid references oauth_refresh_tokens(id), created_at timestamptz not null default now()
);

create table if not exists developer_api_keys (
    id uuid primary key default gen_random_uuid(), app_id uuid not null references developer_apps(id) on delete cascade,
    key_prefix text not null unique, key_hash text not null unique, scopes text[] not null default '{}', active boolean not null default true,
    expires_at timestamptz, last_used_at timestamptz, created_at timestamptz not null default now(), revoked_at timestamptz
);
create index if not exists idx_developer_api_keys_app on developer_api_keys(app_id);

create table if not exists api_rate_buckets (
    subject text not null, bucket_start timestamptz not null, requests bigint not null default 0 check(requests >= 0), primary key(subject,bucket_start)
);
create table if not exists api_usage_counters (
    tenant_id uuid not null references tenants(id) on delete cascade, app_id uuid references developer_apps(id) on delete cascade,
    usage_date date not null, request_count bigint not null default 0 check(request_count >= 0), token_count bigint not null default 0 check(token_count >= 0),
    bytes_in bigint not null default 0 check(bytes_in >= 0), bytes_out bigint not null default 0 check(bytes_out >= 0), primary key(tenant_id,app_id,usage_date)
);

alter table developers enable row level security;
alter table developer_apps enable row level security;
alter table oauth_clients enable row level security;
alter table developer_api_keys enable row level security;
alter table api_usage_counters enable row level security;
alter table oauth_authorization_codes enable row level security;
alter table oauth_access_tokens enable row level security;
alter table oauth_refresh_tokens enable row level security;
alter table api_rate_buckets enable row level security;

create or replace function developer_tenant_id() returns uuid language sql stable as $$
    select tenant_id from developers where user_id=(select auth.uid()) limit 1
$$;
create policy developer_self on developers for select to authenticated using(user_id=(select auth.uid()));
create policy developer_apps_owner on developer_apps for all to authenticated
using(tenant_id=(select developer_tenant_id()) and owner_user_id=(select auth.uid()))
with check(tenant_id=(select developer_tenant_id()) and owner_user_id=(select auth.uid()));
create policy oauth_clients_owner on oauth_clients for all to authenticated
using(app_id in(select id from developer_apps where tenant_id=(select developer_tenant_id()) and owner_user_id=(select auth.uid())))
with check(app_id in(select id from developer_apps where tenant_id=(select developer_tenant_id()) and owner_user_id=(select auth.uid())));
create policy developer_api_keys_owner on developer_api_keys for all to authenticated
using(app_id in(select id from developer_apps where tenant_id=(select developer_tenant_id()) and owner_user_id=(select auth.uid())))
with check(app_id in(select id from developer_apps where tenant_id=(select developer_tenant_id()) and owner_user_id=(select auth.uid())));
create policy api_usage_owner on api_usage_counters for select to authenticated using(tenant_id=(select developer_tenant_id()));

grant select,insert,update,delete on developers,developer_apps,oauth_clients,developer_api_keys to authenticated;
grant select on api_usage_counters to authenticated;
revoke all on oauth_authorization_codes,oauth_access_tokens,oauth_refresh_tokens,api_rate_buckets from anon,authenticated;

create or replace function increment_api_usage(p_tenant_id uuid,p_app_id uuid,p_usage_date date,p_requests bigint default 1,p_tokens bigint default 0,p_bytes_in bigint default 0,p_bytes_out bigint default 0)
returns void language sql security invoker as $$
insert into api_usage_counters(tenant_id,app_id,usage_date,request_count,token_count,bytes_in,bytes_out)
values(p_tenant_id,p_app_id,p_usage_date,p_requests,p_tokens,p_bytes_in,p_bytes_out)
on conflict(tenant_id,app_id,usage_date) do update set
request_count=api_usage_counters.request_count+excluded.request_count,
token_count=api_usage_counters.token_count+excluded.token_count,
bytes_in=api_usage_counters.bytes_in+excluded.bytes_in,bytes_out=api_usage_counters.bytes_out+excluded.bytes_out
$$;

create or replace function consume_api_rate(p_subject text,p_bucket_start timestamptz,p_limit bigint)
returns boolean language plpgsql security invoker as $$
declare current_count bigint;
begin
 insert into api_rate_buckets(subject,bucket_start,requests) values(p_subject,p_bucket_start,1)
 on conflict(subject,bucket_start) do update set requests=api_rate_buckets.requests+1 returning requests into current_count;
 if current_count > p_limit then
   update api_rate_buckets set requests=requests-1 where subject=p_subject and bucket_start=p_bucket_start;
   return false;
 end if;
 return true;
end $$;
revoke all on function consume_api_rate(text,timestamptz,bigint) from anon,authenticated;
