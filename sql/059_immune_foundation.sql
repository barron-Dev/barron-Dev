-- 059_immune_foundation.sql
-- Cyclothone Immune: signed federation foundation.
-- Federation is split into evidence distribution, model learning, and installation.
-- This migration establishes durable trust/lifecycle invariants only.

create table immune_signing_keys (
    kid text primary key check (length(kid) between 8 and 128),
    algorithm text not null check (algorithm = 'ed25519'),
    public_key text not null,
    owner_tenant_id uuid references tenants(id) on delete cascade,
    scope text not null check (scope in ('global','tenant')),
    status text not null default 'active'
        check (status in ('active','retired','revoked')),
    not_before timestamptz not null default now(),
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    check (expires_at is null or expires_at > not_before),
    check ((scope='global' and owner_tenant_id is null) or (scope='tenant' and owner_tenant_id is not null))
);

create table immune_bundles (
    id uuid primary key default gen_random_uuid(),
    version bigint not null,
    kind text not null check (kind in ('rule','ioc','model')),
    schema_version text not null check (length(schema_version) between 1 and 32),
    issuer_tenant_id uuid references tenants(id) on delete set null,
    issuer_kid text not null references immune_signing_keys(kid),
    payload jsonb not null,
    payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
    signature text not null,
    signature_context text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    state text not null default 'pending'
        check (state in ('pending','canary','stable','rolled_back','rejected')),
    rollout_pct numeric(5,2) not null default 0
        check (rollout_pct >= 0 and rollout_pct <= 100),
    min_installations integer not null default 0 check (min_installations >= 0),
    min_quorum integer not null default 0 check (min_quorum >= 0),
    expected_blocks bigint not null default 0 check (expected_blocks >= 0),
    false_positive_estimate numeric(8,6) check (false_positive_estimate is null or (false_positive_estimate >= 0 and false_positive_estimate <= 1)),
    provenance jsonb not null default '{}'::jsonb,
    applies_to text[] not null default '{}',
    countries text[] not null default '{}',
    zk_proof text,
    installs bigint not null default 0 check (installs >= 0),
    blocks_confirmed bigint not null default 0 check (blocks_confirmed >= 0),
    false_positives bigint not null default 0 check (false_positives >= 0),
    updated_at timestamptz not null default now(),
    unique(version),
    check (expires_at > created_at),
    check (jsonb_typeof(payload) = 'object'),
    check (jsonb_typeof(provenance) = 'object'),
    check (state <> 'stable' or rollout_pct = 100),
    check (state <> 'rolled_back' or rollout_pct = 0)
);

create table immune_rounds (
    id uuid primary key default gen_random_uuid(),
    model_kind text not null check (model_kind in ('classifier','embedding','anomaly','behavior')),
    round_number bigint not null check (round_number > 0),
    status text not null default 'collecting'
        check (status in ('collecting','aggregating','published','aborted')),
    min_participants integer not null default 3 check (min_participants >= 2),
    max_participants integer not null default 10000 check (max_participants >= min_participants),
    dp_epsilon numeric(12,6) not null check (dp_epsilon > 0),
    dp_delta numeric(20,18) not null check (dp_delta > 0 and dp_delta < 1),
    clipping_norm numeric(20,8) not null check (clipping_norm > 0),
    max_weight numeric(8,6) not null default 0.25 check (max_weight > 0 and max_weight <= 1),
    bundle_id uuid references immune_bundles(id) on delete set null,
    opened_at timestamptz not null default now(),
    closed_at timestamptz,
    created_at timestamptz not null default now(),
    unique(model_kind, round_number),
    check (closed_at is null or closed_at >= opened_at),
    check ((status='collecting' and closed_at is null) or status <> 'collecting')
);

create table immune_participation (
    id uuid primary key default gen_random_uuid(),
    round_id uuid not null references immune_rounds(id) on delete cascade,
    tenant_id uuid not null references tenants(id) on delete cascade,
    contribution_commitment text not null check (contribution_commitment ~ '^[0-9a-f]{64}$'),
    sample_count integer not null check (sample_count between 1 and 1000000),
    clipped_norm numeric(20,8) not null check (clipped_norm >= 0),
    weight numeric(8,6) not null check (weight > 0 and weight <= 1),
    dp_noise_scale numeric(20,8) not null check (dp_noise_scale >= 0),
    accepted boolean not null default false,
    rejection_reason text,
    created_at timestamptz not null default now(),
    unique(round_id, tenant_id)
);

create table immune_installs (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    bundle_id uuid not null references immune_bundles(id) on delete restrict,
    status text not null default 'offered'
        check (status in ('offered','installed','active','rolled_back','uninstalled','failed')),
    blocks_confirmed bigint not null default 0 check (blocks_confirmed >= 0),
    false_positives bigint not null default 0 check (false_positives >= 0),
    installed_at timestamptz,
    updated_at timestamptz not null default now(),
    unique(tenant_id,bundle_id)
);

create index immune_bundles_state_expiry on immune_bundles(state,expires_at);
create index immune_installs_tenant_state on immune_installs(tenant_id,status);
create index immune_participation_round on immune_participation(round_id,accepted);
create index immune_keys_scope_status on immune_signing_keys(scope,status);

alter table immune_signing_keys enable row level security;
alter table immune_bundles enable row level security;
alter table immune_rounds enable row level security;
alter table immune_participation enable row level security;
alter table immune_installs enable row level security;

create policy immune_bundle_read on immune_bundles for select to authenticated
using (
    state in ('canary','stable')
    and (expires_at > now())
    and (
        cardinality(applies_to)=0
        or coalesce((select auth.jwt()->>'tenant_id'),'') = any(applies_to)
    )
);

create policy immune_round_read on immune_rounds for select to authenticated
using (true);

create policy immune_participation_read on immune_participation for select to authenticated
using (tenant_id = ((select auth.jwt()->>'tenant_id'))::uuid);

create policy immune_install_read on immune_installs for select to authenticated
using (tenant_id = ((select auth.jwt()->>'tenant_id'))::uuid);

revoke all on immune_signing_keys,immune_bundles,immune_rounds,immune_participation,immune_installs
from anon,authenticated;

create or replace function immune_publish_bundle(
    p_version bigint, p_kind text, p_schema_version text,
    p_issuer_tenant uuid, p_kid text, p_payload jsonb,
    p_payload_sha256 text, p_signature text, p_signature_context text,
    p_expires_at timestamptz, p_provenance jsonb default '{}'::jsonb,
    p_applies_to text[] default '{}', p_countries text[] default '{}'
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid; v_scope text; v_owner uuid;
begin
    if p_version is null or p_version <= 0 then raise exception 'invalid bundle version'; end if;
    if p_expires_at <= now() then raise exception 'bundle already expired'; end if;
    if p_payload is null or jsonb_typeof(p_payload) <> 'object' then raise exception 'payload must be object'; end if;
    if p_payload_sha256 !~ '^[0-9a-f]{64}$' then raise exception 'invalid payload hash'; end if;
    select scope,owner_tenant_id into v_scope,v_owner from immune_signing_keys
      where kid=p_kid and status='active' and not_before <= now()
        and (expires_at is null or expires_at > now());
    if not found then raise exception 'untrusted signing key'; end if;
    if v_scope='tenant' and v_owner is distinct from p_issuer_tenant then raise exception 'issuer key tenant mismatch'; end if;
    if v_scope='global' and p_issuer_tenant is not null then raise exception 'global key cannot impersonate tenant issuer'; end if;
    insert into immune_bundles(
      version,kind,schema_version,issuer_tenant_id,issuer_kid,payload,payload_sha256,
      signature,signature_context,expires_at,provenance,applies_to,countries
    ) values (
      p_version,p_kind,p_schema_version,p_issuer_tenant,p_kid,p_payload,p_payload_sha256,
      p_signature,p_signature_context,p_expires_at,coalesce(p_provenance,'{}'::jsonb),
      coalesce(p_applies_to,'{}'),coalesce(p_countries,'{}')
    ) returning id into v_id;
    return v_id;
end;
$$;

create or replace function immune_open_round(
    p_model_kind text,p_round_number bigint,p_min_participants integer,
    p_dp_epsilon numeric,p_dp_delta numeric,p_clipping_norm numeric,
    p_max_weight numeric default 0.25
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid;
begin
    insert into immune_rounds(model_kind,round_number,min_participants,dp_epsilon,dp_delta,clipping_norm,max_weight)
    values(p_model_kind,p_round_number,p_min_participants,p_dp_epsilon,p_dp_delta,p_clipping_norm,p_max_weight)
    returning id into v_id;
    return v_id;
exception when unique_violation then
    raise exception 'round already exists';
end;
$$;

create or replace function immune_submit_participation(
    p_round uuid,p_tenant uuid,p_commitment text,p_sample_count integer,
    p_clipped_norm numeric,p_weight numeric,p_noise_scale numeric
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid; v_status text; v_max integer; v_max_weight numeric;
begin
    select status,max_participants,max_weight into v_status,v_max,v_max_weight
      from immune_rounds where id=p_round for update;
    if not found then raise exception 'unknown round'; end if;
    if v_status <> 'collecting' then raise exception 'round not accepting contributions'; end if;
    if (select count(*) from immune_participation where round_id=p_round and accepted) >= v_max
      then raise exception 'round participant cap reached'; end if;
    if p_commitment !~ '^[0-9a-f]{64}$' then raise exception 'invalid contribution commitment'; end if;
    if p_sample_count < 1 or p_sample_count > 1000000 then raise exception 'invalid sample count'; end if;
    if p_clipped_norm < 0 or p_weight <= 0 or p_weight > v_max_weight or p_noise_scale < 0
      then raise exception 'invalid bounded contribution'; end if;
    insert into immune_participation(round_id,tenant_id,contribution_commitment,sample_count,clipped_norm,weight,dp_noise_scale,accepted)
      values(p_round,p_tenant,p_commitment,p_sample_count,p_clipped_norm,p_weight,p_noise_scale,true)
      on conflict(round_id,tenant_id) do update set
        contribution_commitment=excluded.contribution_commitment,
        sample_count=excluded.sample_count,clipped_norm=excluded.clipped_norm,
        weight=excluded.weight,dp_noise_scale=excluded.dp_noise_scale,
        accepted=true,rejection_reason=null
      returning id into v_id;
    return v_id;
end;
$$;

create or replace function immune_record_install(
    p_tenant uuid,p_bundle uuid,p_status text
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid; old_status text; bundle_state text;
begin
    select state into bundle_state from immune_bundles where id=p_bundle;
    if not found then raise exception 'unknown bundle'; end if;
    if bundle_state not in ('canary','stable','rolled_back') then raise exception 'bundle not installable'; end if;
    select id,status into v_id,old_status from immune_installs where tenant_id=p_tenant and bundle_id=p_bundle for update;
    if old_status is not null then
      if old_status='rolled_back' and p_status not in ('uninstalled') then raise exception 'invalid install transition'; end if;
      if old_status='active' and p_status not in ('active','rolled_back','uninstalled') then raise exception 'invalid install transition'; end if;
      if old_status='installed' and p_status not in ('installed','active','failed','rolled_back') then raise exception 'invalid install transition'; end if;
    end if;
    if v_id is null then
      insert into immune_installs(tenant_id,bundle_id,status,installed_at)
      values(p_tenant,p_bundle,p_status,case when p_status in ('installed','active') then now() end)
      returning id into v_id;
    else
      update immune_installs set status=p_status,updated_at=now(),
        installed_at=case when installed_at is null and p_status in ('installed','active') then now() else installed_at end
      where id=v_id;
    end if;
    return v_id;
end;
$$;

create or replace function immune_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public
as $$
select jsonb_build_object(
 'bundles_available',(select count(*) from immune_bundles where state in ('canary','stable') and expires_at>now()
   and (cardinality(applies_to)=0 or p_tenant::text=any(applies_to))),
 'installs',(select count(*) from immune_installs where tenant_id=p_tenant),
 'active_installs',(select count(*) from immune_installs where tenant_id=p_tenant and status='active'),
 'rounds_participated',(select count(*) from immune_participation where tenant_id=p_tenant and accepted)
);
$$;

revoke all on function immune_publish_bundle(bigint,text,text,uuid,text,jsonb,text,text,text,timestamptz,jsonb,text[],text[]) from public,anon,authenticated;
revoke all on function immune_open_round(text,bigint,integer,numeric,numeric,numeric,numeric) from public,anon,authenticated;
revoke all on function immune_submit_participation(uuid,uuid,text,integer,numeric,numeric,numeric) from public,anon,authenticated;
revoke all on function immune_record_install(uuid,uuid,text) from public,anon,authenticated;
revoke all on function immune_stats(uuid) from public,anon,authenticated;
grant execute on function immune_publish_bundle(bigint,text,text,uuid,text,jsonb,text,text,text,timestamptz,jsonb,text[],text[]) to service_role;
grant execute on function immune_open_round(text,bigint,integer,numeric,numeric,numeric,numeric) to service_role;
grant execute on function immune_submit_participation(uuid,uuid,text,integer,numeric,numeric,numeric) to service_role;
grant execute on function immune_record_install(uuid,uuid,text) to service_role;
grant execute on function immune_stats(uuid) to service_role;
