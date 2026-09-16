-- Sentinel Threat Intelligence Federation, migration 029.
-- Federation is an intelligence exchange layer only. Inbound intelligence must
-- enter the existing Detection -> AutoCase -> Response pipeline; this migration
-- does not create a parallel case-management path.

create table if not exists public.federation_peers (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references public.tenants(id) on delete cascade,
    external_id text,
    name text not null check (length(trim(name)) between 1 and 240),
    kind text not null check (kind in ('tenant','cert','isac','vendor','research')),
    country text,
    taxii_url text,
    taxii_collection text,
    auth_ref text,
    trust_level integer not null default 1 check (trust_level between 0 and 3),
    reputation real not null default 0.5 check (reputation between 0 and 1),
    share_categories text[] not null default '{}',
    receive_categories text[] not null default '{}',
    require_anonymization boolean not null default true,
    status text not null default 'pending'
        check (status in ('active','paused','blocked','pending')),
    last_share_at timestamptz,
    last_receive_at timestamptz,
    created_at timestamptz not null default now(),
    check (
        (kind = 'tenant' and tenant_id is not null and external_id is null)
        or
        (kind <> 'tenant' and tenant_id is null and external_id is not null)
    ),
    check (taxii_url is null or taxii_url ~ '^https://[^[:space:]]+$')
);
create unique index if not exists federation_peers_tenant_uidx
    on public.federation_peers(tenant_id) where tenant_id is not null;
create unique index if not exists federation_peers_external_uidx
    on public.federation_peers(external_id) where external_id is not null;
create index if not exists federation_peers_status_idx
    on public.federation_peers(status, trust_level);

create table if not exists public.fed_indicators (
    id uuid primary key default gen_random_uuid(),
    source_peer_id uuid references public.federation_peers(id) on delete set null,
    source_tenant uuid references public.tenants(id) on delete set null,
    ioc_type text not null check (ioc_type in (
        'sha256','domain','ipv4','ipv6','url','email','ja3','btc_address','mutex'
    )),
    value_hash text not null check (value_hash ~ '^[0-9a-f]{64}$'),
    value_ref text,
    category text,
    severity text not null default 'medium'
        check (severity in ('low','medium','high','critical')),
    confidence real not null default 0.5 check (confidence between 0 and 1),
    sightings integer not null default 1 check (sightings >= 1),
    distinct_peers integer not null default 1 check (distinct_peers >= 1),
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    expires_at timestamptz,
    verified boolean not null default false,
    whitelisted boolean not null default false,
    created_at timestamptz not null default now(),
    unique (ioc_type, value_hash)
);
create index if not exists fed_indicators_lookup_idx
    on public.fed_indicators(ioc_type, value_hash);
create index if not exists fed_indicators_verified_idx
    on public.fed_indicators(verified) where verified = true;
create index if not exists fed_indicators_peer_idx
    on public.fed_indicators(source_peer_id);

-- One canonical indicator can be observed by many peers. This is required for
-- correct distinct-peer verification and prevents the canonical row's single
-- source_peer_id from being used as a false representation of provenance.
create table if not exists public.fed_indicator_observations (
    indicator_id uuid not null references public.fed_indicators(id) on delete cascade,
    peer_id uuid not null references public.federation_peers(id) on delete cascade,
    source_tenant uuid references public.tenants(id) on delete set null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    accepted boolean,
    rejected_reason text,
    created_at timestamptz not null default now(),
    primary key (indicator_id, peer_id)
);
create index if not exists fed_indicator_observations_peer_idx
    on public.fed_indicator_observations(peer_id, last_seen desc);

create table if not exists public.fed_trust_edges (
    from_peer_id uuid not null references public.federation_peers(id) on delete cascade,
    to_peer_id uuid not null references public.federation_peers(id) on delete cascade,
    shared_count integer not null default 0 check (shared_count >= 0),
    accepted_count integer not null default 0 check (accepted_count >= 0),
    rejected_count integer not null default 0 check (rejected_count >= 0),
    reputation real not null default 0.5 check (reputation between 0 and 1),
    updated_at timestamptz not null default now(),
    primary key (from_peer_id, to_peer_id),
    check (from_peer_id <> to_peer_id)
);

create table if not exists public.fed_shares (
    id bigserial primary key,
    peer_id uuid not null references public.federation_peers(id) on delete cascade,
    direction text not null check (direction in ('outbound','inbound')),
    ioc_count integer not null check (ioc_count >= 0),
    categories text[] not null default '{}',
    anonymized boolean not null default true,
    status text not null default 'success'
        check (status in ('success','partial','failed','rejected')),
    error text,
    payload_sha256 text check (payload_sha256 is null or payload_sha256 ~ '^[0-9a-f]{64}$'),
    ts timestamptz not null default now()
);
create index if not exists fed_shares_peer_idx
    on public.fed_shares(peer_id, ts desc);

create table if not exists public.fed_poisoning_events (
    id uuid primary key default gen_random_uuid(),
    peer_id uuid not null references public.federation_peers(id) on delete cascade,
    ioc_hash text not null check (ioc_hash ~ '^[0-9a-f]{64}$'),
    reason text not null check (reason in ('false_positive','targeted','low_quality')),
    reporter_tenant uuid references public.tenants(id) on delete set null,
    details jsonb not null default '{}'::jsonb,
    ts timestamptz not null default now()
);
create index if not exists fed_poisoning_peer_idx
    on public.fed_poisoning_events(peer_id, ts desc);

alter table public.federation_peers enable row level security;
alter table public.fed_indicators enable row level security;
alter table public.fed_indicator_observations enable row level security;
alter table public.fed_trust_edges enable row level security;
alter table public.fed_shares enable row level security;
alter table public.fed_poisoning_events enable row level security;

-- Federation data contains cross-tenant provenance and integration metadata.
-- Customer-facing access is intentionally mediated by authenticated Sentinel
-- API routes using the existing principal/tenant authorization layer. No direct
-- browser access is granted to these tables.
revoke all on public.federation_peers,
    public.fed_indicators,
    public.fed_indicator_observations,
    public.fed_trust_edges,
    public.fed_shares,
    public.fed_poisoning_events from anon, authenticated;
grant all on public.federation_peers,
    public.fed_indicators,
    public.fed_indicator_observations,
    public.fed_trust_edges,
    public.fed_shares,
    public.fed_poisoning_events to service_role;

create or replace function public.federation_severity_rank(p_severity text)
returns integer
language sql
immutable
strict
set search_path = pg_catalog
as $$
    select case p_severity
        when 'low' then 1
        when 'medium' then 2
        when 'high' then 3
        when 'critical' then 4
        else 0
    end
$$;
revoke all on function public.federation_severity_rank(text) from public, anon, authenticated;
grant execute on function public.federation_severity_rank(text) to service_role;

create or replace function public.upsert_fed_indicator(
    p_peer uuid,
    p_tenant uuid,
    p_ioc_type text,
    p_value_hash text,
    p_value_ref text,
    p_category text,
    p_severity text,
    p_confidence real
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_id uuid;
    v_peer_kind text;
    v_peer_tenant uuid;
    v_distinct_peers integer;
    v_severity text;
    v_existing_confidence real;
begin
    if p_peer is null or p_value_hash is null then
        raise exception 'peer and value_hash are required';
    end if;
    if p_value_hash !~ '^[0-9a-f]{64}$' then
        raise exception 'value_hash must be lowercase SHA-256 hex';
    end if;
    if p_ioc_type not in ('sha256','domain','ipv4','ipv6','url','email','ja3','btc_address','mutex') then
        raise exception 'unsupported IOC type';
    end if;
    if p_severity not in ('low','medium','high','critical') then
        raise exception 'invalid severity';
    end if;
    if p_confidence is null or p_confidence < 0 or p_confidence > 1 then
        raise exception 'invalid confidence';
    end if;

    select kind, tenant_id into v_peer_kind, v_peer_tenant
      from public.federation_peers
     where id = p_peer and status = 'active'
     for update;
    if not found then
        raise exception 'peer is not active';
    end if;

    if v_peer_kind = 'tenant' and v_peer_tenant is distinct from p_tenant then
        raise exception 'tenant peer binding mismatch';
    end if;
    if v_peer_kind <> 'tenant' and p_tenant is not null then
        raise exception 'external peer cannot be bound to a tenant';
    end if;

    insert into public.fed_indicators (
        source_peer_id, source_tenant, ioc_type, value_hash,
        value_ref, category, severity, confidence
    ) values (
        p_peer, p_tenant, p_ioc_type, p_value_hash,
        p_value_ref, p_category, p_severity, p_confidence
    )
    on conflict (ioc_type, value_hash) do update
       set last_seen = now(),
           category = coalesce(excluded.category, public.fed_indicators.category),
           severity = case
               when public.federation_severity_rank(excluded.severity)
                    > public.federation_severity_rank(public.fed_indicators.severity)
               then excluded.severity
               else public.fed_indicators.severity
           end,
           confidence = greatest(public.fed_indicators.confidence, excluded.confidence),
           value_ref = coalesce(public.fed_indicators.value_ref, excluded.value_ref)
    returning id, confidence into v_id, v_existing_confidence;

    insert into public.fed_indicator_observations (
        indicator_id, peer_id, source_tenant
    ) values (
        v_id, p_peer, p_tenant
    )
    on conflict (indicator_id, peer_id) do update
       set last_seen = now(),
           source_tenant = coalesce(public.fed_indicator_observations.source_tenant, excluded.source_tenant);

    select count(*)::integer into v_distinct_peers
      from public.fed_indicator_observations
     where indicator_id = v_id;

    update public.fed_indicators
       set sightings = (
               select count(*)::integer
                 from public.fed_indicator_observations
                where indicator_id = v_id
           ),
           distinct_peers = greatest(v_distinct_peers, 1),
           verified = (v_distinct_peers >= 3)
     where id = v_id;

    return v_id;
end;
$$;
revoke all on function public.upsert_fed_indicator(uuid, uuid, text, text, text, text, text, real)
    from public, anon, authenticated;
grant execute on function public.upsert_fed_indicator(uuid, uuid, text, text, text, text, text, real)
    to service_role;

create or replace function public.record_fed_peer_result(
    p_from_peer uuid,
    p_to_peer uuid,
    p_accepted boolean
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_shared integer;
    v_accepted integer;
    v_rejected integer;
    v_rep real;
begin
    if p_from_peer is null or p_to_peer is null or p_from_peer = p_to_peer then
        raise exception 'invalid peer edge';
    end if;

    insert into public.fed_trust_edges (
        from_peer_id, to_peer_id, shared_count, accepted_count, rejected_count, reputation
    ) values (
        p_from_peer, p_to_peer, 1,
        case when p_accepted then 1 else 0 end,
        case when p_accepted then 0 else 1 end,
        case when p_accepted then 1.0 else 0.0 end
    )
    on conflict (from_peer_id, to_peer_id) do update
       set shared_count = public.fed_trust_edges.shared_count + 1,
           accepted_count = public.fed_trust_edges.accepted_count + case when p_accepted then 1 else 0 end,
           rejected_count = public.fed_trust_edges.rejected_count + case when p_accepted then 0 else 1 end,
           reputation = (
               (public.fed_trust_edges.accepted_count + case when p_accepted then 1 else 0 end)::real
               /
               greatest(
                   public.fed_trust_edges.accepted_count
                   + case when p_accepted then 1 else 0 end
                   + public.fed_trust_edges.rejected_count
                   + case when p_accepted then 0 else 1 end,
                   1
               )::real
           ),
           updated_at = now();

    select shared_count, accepted_count, rejected_count, reputation
      into v_shared, v_accepted, v_rejected, v_rep
      from public.fed_trust_edges
     where from_peer_id = p_from_peer and to_peer_id = p_to_peer;
end;
$$;
revoke all on function public.record_fed_peer_result(uuid, uuid, boolean) from public, anon, authenticated;
grant execute on function public.record_fed_peer_result(uuid, uuid, boolean) to service_role;

create or replace function public.recompute_peer_reputation(p_peer uuid)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    accepted integer;
    rejected integer;
    poisoned integer;
    v_rep real;
begin
    select coalesce(sum(accepted_count), 0), coalesce(sum(rejected_count), 0)
      into accepted, rejected
      from public.fed_trust_edges
     where from_peer_id = p_peer;

    select count(*)::integer into poisoned
      from public.fed_poisoning_events
     where peer_id = p_peer
       and ts > now() - interval '30 days';

    if accepted + rejected = 0 then
        v_rep := 0.5;
    else
        v_rep := accepted::real / (accepted + rejected)::real;
    end if;

    v_rep := v_rep * (1.0 - least(poisoned * 0.1, 0.5));

    update public.federation_peers
       set reputation = v_rep
     where id = p_peer;
end;
$$;
revoke all on function public.recompute_peer_reputation(uuid) from public, anon, authenticated;
grant execute on function public.recompute_peer_reputation(uuid) to service_role;

-- Federation share history is immutable evidence.
create or replace function public.fed_shares_immutable()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'federation share log is immutable';
end;
$$;
revoke all on function public.fed_shares_immutable() from public, anon, authenticated;
create trigger fed_shares_immutable
before update or delete on public.fed_shares
for each row execute function public.fed_shares_immutable();

-- No unverified third-party endpoints are seeded here. External peer endpoints
-- and credentials must be explicitly configured and validated by the federation
-- service before activation.
