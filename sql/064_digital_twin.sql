-- Digital Twin foundation: tenant-scoped topology + durable simulation records.
-- Simulations are advisory only; this migration grants no execution authority.

create table twin_nodes (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    node_type text not null check (node_type in (
        'device','user','process','file','network','service','database','credential',
        'endpoint','container','ot_device','camera','door','account','session'
    )),
    external_id text not null check (length(btrim(external_id)) between 1 and 512),
    label text check (label is null or length(label) <= 512),
    criticality real not null default 0.5 check (criticality >= 0 and criticality <= 1),
    attributes jsonb not null default '{}'::jsonb check (jsonb_typeof(attributes) = 'object'),
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    unique (tenant_id, node_type, external_id)
);

create index idx_twin_nodes_tenant_type on twin_nodes(tenant_id, node_type, id);
create index idx_twin_nodes_tenant_ext on twin_nodes(tenant_id, external_id);

create table twin_edges (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    source_id uuid not null references twin_nodes(id) on delete cascade,
    target_id uuid not null references twin_nodes(id) on delete cascade,
    relation text not null check (relation in (
        'runs','runs_on','connects_to','reads','writes','executes','authenticates',
        'owns','depends_on','hosts','manages','trusts','controls'
    )),
    weight real not null default 1.0 check (weight >= 0 and weight <= 10),
    criticality real not null default 0.5 check (criticality >= 0 and criticality <= 1),
    last_seen timestamptz not null default now(),
    unique (source_id, target_id, relation),
    check (source_id <> target_id)
);

create index idx_twin_edges_tenant_src on twin_edges(tenant_id, source_id, relation);
create index idx_twin_edges_tenant_dst on twin_edges(tenant_id, target_id, relation);

create table twin_simulations (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    action text not null check (action in (
        'isolate_host','kill_process','quarantine_file','disable_account',
        'force_logout','block_hash','block_ip'
    )),
    target_node_id uuid not null references twin_nodes(id) on delete cascade,
    args jsonb not null default '{}'::jsonb check (jsonb_typeof(args) = 'object'),
    requested_by uuid references auth.users(id) on delete set null,
    status text not null default 'pending'
        check (status in ('pending','running','complete','failed')),
    impact_score real check (impact_score is null or (impact_score >= 0 and impact_score <= 1)),
    cascade_size integer check (cascade_size is null or (cascade_size >= 0 and cascade_size <= 1000000)),
    affected_nodes jsonb not null default '[]'::jsonb
        check (jsonb_typeof(affected_nodes) = 'array' and jsonb_array_length(affected_nodes) <= 500),
    critical_impact jsonb not null default '[]'::jsonb
        check (jsonb_typeof(critical_impact) = 'array' and jsonb_array_length(critical_impact) <= 100),
    recommendation text check (recommendation is null or length(recommendation) <= 2000),
    duration_ms integer check (duration_ms is null or duration_ms >= 0),
    created_at timestamptz not null default now()
);

create index idx_twin_sim_tenant_created on twin_simulations(tenant_id, created_at desc);
create index idx_twin_sim_tenant_target on twin_simulations(tenant_id, target_node_id);

alter table twin_nodes enable row level security;
alter table twin_edges enable row level security;
alter table twin_simulations enable row level security;

create policy twin_nodes_select on twin_nodes
    for select to authenticated
    using ((select auth.jwt() ->> 'tenant_id')::uuid = tenant_id);
create policy twin_edges_select on twin_edges
    for select to authenticated
    using ((select auth.jwt() ->> 'tenant_id')::uuid = tenant_id);
create policy twin_simulations_select on twin_simulations
    for select to authenticated
    using ((select auth.jwt() ->> 'tenant_id')::uuid = tenant_id);

create or replace function twin_validate_edge_tenant()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    v_source_tenant uuid;
    v_target_tenant uuid;
begin
    select tenant_id into v_source_tenant from twin_nodes where id = new.source_id;
    select tenant_id into v_target_tenant from twin_nodes where id = new.target_id;
    if v_source_tenant is null or v_target_tenant is null
       or v_source_tenant <> new.tenant_id or v_target_tenant <> new.tenant_id then
        raise exception 'twin edge tenant mismatch';
    end if;
    return new;
end;
$$;

drop trigger if exists trg_twin_validate_edge_tenant on twin_edges;
create trigger trg_twin_validate_edge_tenant
before insert or update on twin_edges
for each row execute function twin_validate_edge_tenant();

revoke all on table twin_nodes, twin_edges, twin_simulations from public, anon, authenticated;
grant select, insert, update on twin_nodes to service_role;
grant select, insert, update on twin_edges to service_role;
grant select, insert, update on twin_simulations to service_role;
revoke all on function twin_validate_edge_tenant() from public, anon, authenticated;

create or replace function twin_upsert_node(
    p_tenant uuid, p_node_type text, p_external_id text,
    p_label text, p_criticality real, p_attributes jsonb
)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid;
begin
    if p_tenant is null or not exists (select 1 from tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_external_id is null or length(btrim(p_external_id)) = 0 or length(p_external_id) > 512 then
        raise exception 'invalid external_id';
    end if;
    if p_attributes is null or jsonb_typeof(p_attributes) <> 'object' then
        raise exception 'attributes must be a JSON object';
    end if;
    if p_criticality is null or p_criticality < 0 or p_criticality > 1 then
        raise exception 'criticality must be between 0 and 1';
    end if;
    insert into twin_nodes(tenant_id,node_type,external_id,label,criticality,attributes)
    values(p_tenant,btrim(p_node_type),btrim(p_external_id),p_label,p_criticality,p_attributes)
    on conflict (tenant_id,node_type,external_id) do update
    set last_seen=now(), label=coalesce(excluded.label,twin_nodes.label),
        criticality=greatest(twin_nodes.criticality,excluded.criticality),
        attributes=twin_nodes.attributes || excluded.attributes
    returning id into v_id;
    return v_id;
end;
$$;
revoke all on function twin_upsert_node(uuid,text,text,text,real,jsonb) from public, anon, authenticated;
grant execute on function twin_upsert_node(uuid,text,text,text,real,jsonb) to service_role;

create or replace function twin_upsert_edge(
    p_tenant uuid, p_source uuid, p_target uuid,
    p_relation text, p_weight real, p_criticality real
)
returns void
language plpgsql security definer set search_path = public
as $$
declare v_source_tenant uuid; v_target_tenant uuid;
begin
    select tenant_id into v_source_tenant from twin_nodes where id=p_source;
    select tenant_id into v_target_tenant from twin_nodes where id=p_target;
    if p_tenant is null or p_source is null or p_target is null or p_source=p_target
       or v_source_tenant is null or v_target_tenant is null
       or v_source_tenant <> p_tenant or v_target_tenant <> p_tenant then
        raise exception 'twin edge tenant mismatch';
    end if;
    if p_weight is null or p_weight < 0 or p_weight > 10 then raise exception 'edge weight out of range'; end if;
    if p_criticality is null or p_criticality < 0 or p_criticality > 1 then raise exception 'edge criticality out of range'; end if;
    insert into twin_edges(tenant_id,source_id,target_id,relation,weight,criticality)
    values(p_tenant,p_source,p_target,p_relation,p_weight,p_criticality)
    on conflict(source_id,target_id,relation) do update
    set tenant_id=excluded.tenant_id,last_seen=now(),
        weight=greatest(twin_edges.weight,excluded.weight),
        criticality=greatest(twin_edges.criticality,excluded.criticality);
end;
$$;
revoke all on function twin_upsert_edge(uuid,uuid,uuid,text,real,real) from public, anon, authenticated;
grant execute on function twin_upsert_edge(uuid,uuid,uuid,text,real,real) to service_role;

create or replace function twin_record_simulation(
    p_tenant uuid,p_action text,p_target_node uuid,p_args jsonb,p_requested_by uuid,
    p_status text,p_impact_score real,p_cascade_size integer,p_affected_nodes jsonb,
    p_critical_impact jsonb,p_recommendation text,p_duration_ms integer
)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid; v_target_tenant uuid;
begin
    select tenant_id into v_target_tenant from twin_nodes where id=p_target_node;
    if v_target_tenant is null or v_target_tenant <> p_tenant then raise exception 'target node tenant mismatch'; end if;
    if p_args is null or jsonb_typeof(p_args) <> 'object' then raise exception 'args must be object'; end if;
    if p_affected_nodes is null or jsonb_typeof(p_affected_nodes) <> 'array' or jsonb_array_length(p_affected_nodes)>500 then raise exception 'affected_nodes invalid'; end if;
    if p_critical_impact is null or jsonb_typeof(p_critical_impact) <> 'array' or jsonb_array_length(p_critical_impact)>100 then raise exception 'critical_impact invalid'; end if;
    if p_status not in ('pending','running','complete','failed') then raise exception 'invalid simulation status'; end if;
    if p_impact_score is not null and (p_impact_score<0 or p_impact_score>1) then raise exception 'impact out of range'; end if;
    if p_cascade_size is not null and (p_cascade_size<0 or p_cascade_size>1000000) then raise exception 'cascade size out of range'; end if;
    if p_duration_ms is not null and p_duration_ms<0 then raise exception 'duration out of range'; end if;
    insert into twin_simulations(
        tenant_id,action,target_node_id,args,requested_by,status,impact_score,cascade_size,
        affected_nodes,critical_impact,recommendation,duration_ms
    ) values (
        p_tenant,p_action,p_target_node,p_args,p_requested_by,p_status,p_impact_score,p_cascade_size,
        p_affected_nodes,p_critical_impact,p_recommendation,p_duration_ms
    ) returning id into v_id;
    return v_id;
end;
$$;
revoke all on function twin_record_simulation(uuid,text,uuid,jsonb,uuid,text,real,integer,jsonb,jsonb,text,integer)
from public, anon, authenticated;
grant execute on function twin_record_simulation(uuid,text,uuid,jsonb,uuid,text,real,integer,jsonb,jsonb,text,integer) to service_role;

create or replace function twin_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public
as $$
    select jsonb_build_object(
        'nodes',(select count(*) from twin_nodes where tenant_id=p_tenant),
        'edges',(select count(*) from twin_edges where tenant_id=p_tenant),
        'simulations',(select count(*) from twin_simulations where tenant_id=p_tenant),
        'avg_impact',(select coalesce(avg(impact_score),0) from twin_simulations where tenant_id=p_tenant and status='complete')
    );
$$;
revoke all on function twin_stats(uuid) from public, anon, authenticated;
grant execute on function twin_stats(uuid) to service_role;
