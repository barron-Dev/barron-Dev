-- Knowledge Engine foundation: global knowledge graph, guides, contextual hints,
-- deterministic recommendations, support tickets, and bounded lexical search.
-- Pricing and branding are intentionally NOT part of this migration.

create table kg_nodes (
    id text primary key check (length(btrim(id)) between 1 and 160),
    kind text not null check (kind in (
        'service','feature','api','guide','concept','integration','pricing',
        'partner','defense','action'
    )),
    label text not null check (length(btrim(label)) between 1 and 300),
    summary text check (summary is null or length(summary) <= 4000),
    service_id text,
    tags text[] not null default '{}',
    embedding real[],
    metadata jsonb not null default '{}'::jsonb
        check (jsonb_typeof(metadata) = 'object'),
    priority integer not null default 100 check (priority >= 0 and priority <= 100000)
);

create index kg_nodes_kind_priority on kg_nodes(kind, priority, id);
create index kg_nodes_service on kg_nodes(service_id);
create index kg_nodes_tags on kg_nodes using gin(tags);
create index kg_nodes_fts on kg_nodes using gin (
    to_tsvector('simple',
        coalesce(label,'') || ' ' ||
        coalesce(summary,'') || ' ' ||
        coalesce(array_to_string(tags,' '),''))
);

create table kg_edges (
    src_id text not null references kg_nodes(id) on delete cascade,
    dst_id text not null references kg_nodes(id) on delete cascade,
    relation text not null check (relation in (
        'explains','includes','requires','integrates_with','priced_as',
        'governs','supersedes','belongs_to','guides','precedes','related_to'
    )),
    weight real not null default 1.0 check (weight >= 0 and weight <= 10),
    primary key (src_id, dst_id, relation),
    check (src_id <> dst_id)
);

create index kg_edges_src on kg_edges(src_id, relation, dst_id);
create index kg_edges_dst on kg_edges(dst_id, relation, src_id);

create table guides (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{0,119}$'),
    title text not null check (length(btrim(title)) between 1 and 300),
    summary text check (summary is null or length(summary) <= 4000),
    audience text not null check (audience in ('visitor','client','partner','developer','admin')),
    category text not null check (length(btrim(category)) between 1 and 120),
    estimated_minutes integer not null default 5 check (estimated_minutes between 1 and 1440),
    difficulty text not null default 'beginner'
        check (difficulty in ('beginner','intermediate','advanced')),
    prerequisite_ids uuid[] not null default '{}',
    tags text[] not null default '{}',
    enabled boolean not null default true,
    priority integer not null default 100 check (priority >= 0 and priority <= 100000),
    created_at timestamptz not null default now()
);

create index guides_audience_priority on guides(audience, priority, slug);
create index guides_tags on guides using gin(tags);

create table guide_steps (
    id uuid primary key default gen_random_uuid(),
    guide_id uuid not null references guides(id) on delete cascade,
    step_no integer not null check (step_no >= 1 and step_no <= 500),
    title text not null check (length(btrim(title)) between 1 and 300),
    body_md text not null check (length(body_md) <= 20000),
    action_url text check (action_url is null or length(action_url) <= 2000),
    action_label text check (action_label is null or length(action_label) <= 200),
    verify_kind text check (verify_kind in ('none','api_call','page_state','code_entered')),
    verify_payload jsonb not null default '{}'::jsonb
        check (jsonb_typeof(verify_payload) = 'object'),
    unique (guide_id, step_no)
);

create index guide_steps_guide on guide_steps(guide_id, step_no);

create table context_hints (
    id uuid primary key default gen_random_uuid(),
    page_route text not null check (length(btrim(page_route)) between 1 and 500),
    element_key text not null check (length(btrim(element_key)) between 1 and 200),
    title text not null check (length(btrim(title)) between 1 and 300),
    body_md text not null check (length(body_md) <= 12000),
    guide_slug text references guides(slug) on delete set null,
    doc_url text check (doc_url is null or length(doc_url) <= 2000),
    api_url text check (api_url is null or length(api_url) <= 2000),
    audience text[] not null default array['client'],
    priority integer not null default 100 check (priority >= 0 and priority <= 100000),
    unique (page_route, element_key)
);

create index context_hints_route_priority on context_hints(page_route, priority, element_key);
create index context_hints_audience on context_hints using gin(audience);

create table recommendation_rules (
    id uuid primary key default gen_random_uuid(),
    name text not null check (length(btrim(name)) between 1 and 300),
    condition jsonb not null check (jsonb_typeof(condition) = 'object'),
    kind text not null check (kind in (
        'enable_service','read_guide','add_partner','upgrade_plan',
        'configure_api','invite_team','harden_setting'
    )),
    target jsonb not null check (jsonb_typeof(target) = 'object'),
    title text not null check (length(btrim(title)) between 1 and 300),
    body_md text not null check (length(body_md) <= 12000),
    cta_label text check (cta_label is null or length(cta_label) <= 200),
    cta_url text check (cta_url is null or length(cta_url) <= 2000),
    base_score real not null default 0.5 check (base_score >= 0 and base_score <= 1),
    priority integer not null default 100 check (priority >= 0 and priority <= 100000),
    enabled boolean not null default true,
    created_at timestamptz not null default now()
);

create index recommendation_rules_active on recommendation_rules(enabled, priority, id);

create table recommendation_impressions (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references tenants(id) on delete cascade,
    user_id uuid references auth.users(id) on delete set null,
    rule_id uuid not null references recommendation_rules(id) on delete cascade,
    shown_at timestamptz not null default now(),
    clicked boolean not null default false,
    clicked_at timestamptz,
    check ((clicked = false and clicked_at is null) or (clicked = true and clicked_at is not null))
);

create index recommendation_impressions_tenant on recommendation_impressions(tenant_id, shown_at desc);
create index recommendation_impressions_rule on recommendation_impressions(tenant_id, rule_id, shown_at desc);

create table tickets (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    opened_by uuid references auth.users(id) on delete set null,
    subject text not null check (length(btrim(subject)) between 1 and 500),
    body text not null check (length(body) between 1 and 50000),
    severity text not null default 'normal'
        check (severity in ('low','normal','high','critical')),
    status text not null default 'open'
        check (status in ('open','pending','escalated','resolved','closed')),
    assigned_to uuid references admin_users(user_id) on delete set null,
    related_service text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index tickets_tenant_created on tickets(tenant_id, created_at desc);
create index tickets_assign_status on tickets(assigned_to, status, created_at desc);

create table ticket_messages (
    id bigint generated always as identity primary key,
    ticket_id uuid not null references tickets(id) on delete cascade,
    author_id uuid not null,
    author_kind text not null check (author_kind in ('client','admin')),
    body text not null check (length(body) between 1 and 50000),
    attachments jsonb not null default '[]'::jsonb
        check (jsonb_typeof(attachments) = 'array'),
    created_at timestamptz not null default now()
);

create index ticket_messages_ticket_created on ticket_messages(ticket_id, created_at, id);

do $$
begin
    if to_regclass('public.admin_users') is not null then
        alter table public.admin_users
            add column if not exists sector text,
            add column if not exists on_call boolean not null default false,
            add column if not exists timezone text not null default 'UTC';
        alter table public.admin_users
            drop constraint if exists admin_users_sector_check;
        alter table public.admin_users
            add constraint admin_users_sector_check check (
                sector is null or sector in (
                    'ops','support','billing','security','compliance','engineering','root'
                )
            );
    end if;
end $$;

alter table kg_nodes enable row level security;
alter table kg_edges enable row level security;
alter table guides enable row level security;
alter table guide_steps enable row level security;
alter table context_hints enable row level security;
alter table recommendation_rules enable row level security;
alter table recommendation_impressions enable row level security;
alter table tickets enable row level security;
alter table ticket_messages enable row level security;

-- The API is the authorization boundary. No direct Data API access is granted.
revoke all on table kg_nodes, kg_edges, guides, guide_steps, context_hints,
    recommendation_rules, recommendation_impressions, tickets, ticket_messages
    from public, anon, authenticated;
grant select, insert, update, delete on kg_nodes, kg_edges, guides, guide_steps,
    context_hints, recommendation_rules, recommendation_impressions, tickets,
    ticket_messages to service_role;

create or replace function kg_search(p_query text, p_limit integer default 30)
returns table (
    node_id text, kind text, label text, summary text,
    service_id text, deep_link text, score real
)
language sql
stable
set search_path = public
as $$
    with q as (
        select websearch_to_tsquery('simple', left(trim(p_query), 1000)) as tsq
    )
    select
        n.id,
        n.kind,
        n.label,
        n.summary,
        n.service_id,
        case n.kind
            when 'service' then '/services/' || coalesce(n.service_id, n.id)
            when 'api' then '/services/' || coalesce(n.service_id, n.id) || '#api_reference'
            when 'guide' then '/guides/' || coalesce(n.metadata->>'slug', n.id)
            when 'pricing' then '/pricing#' || n.id
            when 'partner' then '/partners'
            else '/services/' || coalesce(n.service_id, '')
        end,
        ts_rank_cd(
            to_tsvector('simple',
                coalesce(n.label,'') || ' ' ||
                coalesce(n.summary,'') || ' ' ||
                coalesce(array_to_string(n.tags,' '),'')
            ),
            q.tsq
        )::real
    from kg_nodes n
    cross join q
    where trim(p_query) <> ''
      and to_tsvector('simple',
            coalesce(n.label,'') || ' ' ||
            coalesce(n.summary,'') || ' ' ||
            coalesce(array_to_string(n.tags,' '),'')
          ) @@ q.tsq
    order by score desc, n.priority asc, n.id asc
    limit least(greatest(coalesce(p_limit, 30), 1), 100);
$$;

revoke all on function kg_search(text, integer) from public, anon, authenticated;
grant execute on function kg_search(text, integer) to service_role;

create or replace function knowledge_record_impression(
    p_tenant uuid, p_user uuid, p_rule uuid
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id bigint;
begin
    if p_tenant is null or not exists (select 1 from tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_rule is null or not exists (
        select 1 from recommendation_rules where id = p_rule and enabled = true
    ) then
        raise exception 'unknown recommendation rule';
    end if;
    insert into recommendation_impressions(tenant_id, user_id, rule_id)
    values (p_tenant, p_user, p_rule)
    returning id into v_id;
    return v_id;
end;
$$;

revoke all on function knowledge_record_impression(uuid, uuid, uuid)
    from public, anon, authenticated;
grant execute on function knowledge_record_impression(uuid, uuid, uuid) to service_role;
