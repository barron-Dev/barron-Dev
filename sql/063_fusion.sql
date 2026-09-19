-- Cyclothone Physical-Cyber Fusion foundation.
-- Migration slot 063 is unused on this development branch.
-- Service mutations are privileged; tenant identity is validated server-side.

create table if not exists public.fusion_edges (
    id bigserial primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    src_kind text not null check (src_kind in
        ('person','device','badge','camera','sensor','door','account','session','vehicle','ot_device')),
    src_id text not null check (length(src_id) between 1 and 256),
    dst_kind text not null check (dst_kind in
        ('person','device','badge','camera','sensor','door','account','session','vehicle','ot_device')),
    dst_id text not null check (length(dst_id) between 1 and 256),
    relation text not null check (relation in
        ('entered','exited','observed_by','opened','authenticated','operated','accompanied','was_near','triggered','unlocked')),
    weight real not null default 1.0 check (weight <> 'NaN'::real and abs(weight) <> 'Infinity'::real and weight > 0 and weight <= 1000000),
    confidence real not null default 0.8 check (confidence <> 'NaN'::real and abs(confidence) <> 'Infinity'::real and confidence >= 0 and confidence <= 1),
    site_id uuid references public.physical_sites(id) on delete set null,
    ts timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object')
);

create index if not exists idx_fusion_edges_src on public.fusion_edges(tenant_id,src_kind,src_id,ts desc);
create index if not exists idx_fusion_edges_dst on public.fusion_edges(tenant_id,dst_kind,dst_id,ts desc);
create index if not exists idx_fusion_edges_ts on public.fusion_edges(tenant_id,ts desc);

create table if not exists public.fusion_correlations (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    kind text not null check (kind in
        ('impossible_travel','dual_presence','orphan_session','shadow_access','tailgating','badge_clone',
         'camera_conflict','door_anomaly','ot_cross_access','badge_revoked_use','schedule_violation')),
    severity text not null default 'high' check (severity in ('medium','high','critical')),
    entity_kind text not null check (entity_kind in
        ('person','device','badge','camera','sensor','door','account','session','vehicle','ot_device')),
    entity_id text not null check (length(entity_id) between 1 and 256),
    evidence jsonb not null default '[]'::jsonb check (jsonb_typeof(evidence) = 'array'),
    distance_km real check (distance_km is null or (distance_km <> 'NaN'::real and abs(distance_km) <> 'Infinity'::real and distance_km >= 0)),
    elapsed_seconds integer check (elapsed_seconds is null or elapsed_seconds >= 0),
    status text not null default 'new'
        check (status in ('new','acknowledged','investigating','resolved','false_positive')),
    case_id uuid references public.crime_cases(id) on delete set null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    check (last_seen >= first_seen)
);

create index if not exists idx_fusion_corr_tenant on public.fusion_correlations(tenant_id,first_seen desc);
create index if not exists idx_fusion_corr_status on public.fusion_correlations(tenant_id,status);
create index if not exists idx_fusion_corr_entity on public.fusion_correlations(tenant_id,kind,entity_kind,entity_id,first_seen desc);

alter table public.fusion_edges enable row level security;
alter table public.fusion_correlations enable row level security;

drop policy if exists fusion_edges_tenant on public.fusion_edges;
create policy fusion_edges_tenant on public.fusion_edges
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists fusion_corr_tenant on public.fusion_correlations;
create policy fusion_corr_tenant on public.fusion_correlations
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on public.fusion_edges from anon, authenticated;
revoke all on public.fusion_correlations from anon, authenticated;
grant select on public.fusion_edges, public.fusion_correlations to authenticated;

create or replace function public.fusion_upsert_edge(
    p_tenant uuid, p_src_kind text, p_src_id text,
    p_dst_kind text, p_dst_id text, p_relation text,
    p_site uuid, p_confidence real, p_metadata jsonb, p_ts timestamptz default now()
) returns bigint
language plpgsql security definer set search_path = public
as $$
declare v_id bigint;
begin
    if not exists (select 1 from public.tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_src_id is null or length(p_src_id) not between 1 and 256
       or p_dst_id is null or length(p_dst_id) not between 1 and 256 then
        raise exception 'invalid entity id';
    end if;
    if p_confidence is null or p_confidence = 'NaN'::real or abs(p_confidence) = 'Infinity'::real or p_confidence < 0 or p_confidence > 1 then
        raise exception 'invalid confidence';
    end if;
    if p_metadata is null or jsonb_typeof(p_metadata) <> 'object' then
        raise exception 'metadata must be an object';
    end if;

    -- A repeated relationship gets a bounded confidence-weighted recurrence score.
    insert into public.fusion_edges
        (tenant_id,src_kind,src_id,dst_kind,dst_id,relation,site_id,weight,confidence,metadata,ts)
    values
        (p_tenant,p_src_kind,p_src_id,p_dst_kind,p_dst_id,p_relation,p_site,1.0,p_confidence,p_metadata,p_ts)
    returning id into v_id;
    return v_id;
end;
$$;

create or replace function public.fusion_open_correlation(
    p_tenant uuid, p_kind text, p_severity text,
    p_entity_kind text, p_entity_id text, p_evidence jsonb,
    p_distance_km real default null, p_elapsed_seconds integer default null,
    p_seen_at timestamptz default now()
) returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid;
begin
    if not exists (select 1 from public.tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_evidence is null or jsonb_typeof(p_evidence) <> 'array' or jsonb_array_length(p_evidence) > 64 then
        raise exception 'invalid evidence';
    end if;

    perform pg_advisory_xact_lock(hashtextextended(
        p_tenant::text || ':' || p_kind || ':' || p_entity_kind || ':' || p_entity_id, 0));

    select id into v_id
      from public.fusion_correlations
     where tenant_id = p_tenant
       and kind = p_kind
       and entity_kind = p_entity_kind
       and entity_id = p_entity_id
       and first_seen > p_seen_at - interval '1 hour'
       and status not in ('resolved','false_positive')
     order by first_seen desc
     limit 1
     for update;

    if v_id is not null then
        update public.fusion_correlations
           set last_seen = greatest(last_seen,p_seen_at),
               severity = case
                   when severity = 'critical' or p_severity = 'critical' then 'critical'
                   when severity = 'high' or p_severity = 'high' then 'high'
                   else 'medium' end,
               evidence = (
                   select coalesce(jsonb_agg(x.value order by x.ord), '[]'::jsonb)
                   from (
                       select value, ord from jsonb_array_elements(evidence) with ordinality
                       union all
                       select value, ord + coalesce((select max(z.ord) from jsonb_array_elements(evidence) with ordinality z),0)
                       from jsonb_array_elements(p_evidence) with ordinality
                   ) x
                   limit 64
               )
         where id = v_id;
        return v_id;
    end if;

    insert into public.fusion_correlations
        (tenant_id,kind,severity,entity_kind,entity_id,evidence,distance_km,elapsed_seconds,first_seen,last_seen)
    values
        (p_tenant,p_kind,p_severity,p_entity_kind,p_entity_id,p_evidence,p_distance_km,p_elapsed_seconds,p_seen_at,p_seen_at)
    returning id into v_id;
    return v_id;
end;
$$;

create or replace function public.fusion_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path = public
as $$
    select jsonb_build_object(
      'edges_24h',(select count(*) from public.fusion_edges where tenant_id=p_tenant and ts>now()-interval '24 hours'),
      'correlations_30d',(select count(*) from public.fusion_correlations where tenant_id=p_tenant and first_seen>now()-interval '30 days'),
      'open_correlations',(select count(*) from public.fusion_correlations where tenant_id=p_tenant and status in ('new','acknowledged','investigating')),
      'critical_open',(select count(*) from public.fusion_correlations where tenant_id=p_tenant and status in ('new','acknowledged','investigating') and severity='critical')
    );
$$;

revoke all on function public.fusion_upsert_edge(uuid,text,text,text,text,text,uuid,real,jsonb,timestamptz) from public;
revoke all on function public.fusion_open_correlation(uuid,text,text,text,text,jsonb,real,integer,timestamptz) from public;
revoke all on function public.fusion_stats(uuid) from public;
grant execute on function public.fusion_upsert_edge(uuid,text,text,text,text,text,uuid,real,jsonb,timestamptz) to service_role;
grant execute on function public.fusion_open_correlation(uuid,text,text,text,text,jsonb,real,integer,timestamptz) to service_role;
grant execute on function public.fusion_stats(uuid) to service_role;
