-- Cyclothone Autonomous Response Agents foundation.
-- Deliberately follows existing response/commands/case_actions primitives.
-- No agent execution occurs in SQL.

create table if not exists auto_agents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text not null check (length(trim(name)) between 1 and 120),
    charter jsonb not null default '{}'::jsonb,
    trigger jsonb not null default '{}'::jsonb,
    reasoning_model text check (reasoning_model is null or length(trim(reasoning_model)) between 1 and 128),
    enabled boolean not null default true,
    status text not null default 'active'
        check (status in ('active','paused','frozen','retired')),
    actions_total bigint not null default 0 check (actions_total >= 0),
    actions_blocked bigint not null default 0 check (actions_blocked >= 0),
    last_action_at timestamptz,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    charter_version bigint not null default 1 check (charter_version > 0)
);

create index if not exists idx_auto_agents_tenant_status
    on auto_agents(tenant_id, status);

create table if not exists auto_agent_decisions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    agent_id uuid not null references auto_agents(id) on delete cascade,
    trigger_kind text not null check (length(trim(trigger_kind)) between 1 and 64),
    trigger_id text not null check (length(trigger_id) between 1 and 256),
    detection_id uuid references detections(id) on delete set null,
    case_id uuid references crime_cases(id) on delete set null,
    proposed_action text not null check (length(trim(proposed_action)) between 1 and 128),
    proposed_args jsonb not null default '{}'::jsonb,
    target_device uuid references devices(id) on delete set null,
    gates jsonb not null default '[]'::jsonb,
    llm_reasoning text,
    llm_model text,
    llm_tokens integer check (llm_tokens is null or llm_tokens >= 0),
    outcome text not null check (outcome in
        ('executed','blocked','queued_for_approval','failed','skipped')),
    block_reason text,
    confidence real check (confidence is null or confidence between 0 and 1),
    case_action_id uuid references case_actions(id) on delete set null,
    command_id uuid references commands(id) on delete set null,
    execution_ref text,
    created_at timestamptz not null default now()
);

create index if not exists idx_auto_agent_decisions_tenant_time
    on auto_agent_decisions(tenant_id, created_at desc);
create index if not exists idx_auto_agent_decisions_agent_time
    on auto_agent_decisions(agent_id, created_at desc);
create index if not exists idx_auto_agent_decisions_outcome
    on auto_agent_decisions(tenant_id, outcome, created_at desc);

create table if not exists auto_agent_rate (
    agent_id uuid primary key references auto_agents(id) on delete cascade,
    window_start timestamptz not null default now(),
    action_count integer not null default 0 check (action_count >= 0)
);

create table if not exists auto_agent_freeze (
    tenant_id uuid primary key references tenants(id) on delete cascade,
    frozen boolean not null default false,
    frozen_at timestamptz,
    frozen_by uuid references auth.users(id) on delete set null,
    reason text check (reason is null or length(reason) <= 500)
);

alter table auto_agents enable row level security;
alter table auto_agent_decisions enable row level security;
alter table auto_agent_rate enable row level security;
alter table auto_agent_freeze enable row level security;

drop policy if exists auto_agents_tenant_select on auto_agents;
create policy auto_agents_tenant_select on auto_agents
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists auto_agent_decisions_tenant_select on auto_agent_decisions;
create policy auto_agent_decisions_tenant_select on auto_agent_decisions
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists auto_agent_freeze_tenant_select on auto_agent_freeze;
create policy auto_agent_freeze_tenant_select on auto_agent_freeze
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on auto_agent_rate from anon, authenticated;
revoke all on auto_agent_decisions from anon, authenticated;
revoke all on auto_agents from anon, authenticated;
revoke all on auto_agent_freeze from anon, authenticated;

-- Atomic reservation: freeze + active state + hourly budget are decided under
-- a row lock. A separate check-then-bump pair would race under concurrency.
create or replace function auto_agent_reserve_action(
    p_agent uuid,
    p_tenant uuid,
    p_limit integer,
    p_window_seconds integer default 3600
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_agent auto_agents%rowtype;
    v_frozen boolean;
    v_now timestamptz := now();
    v_count integer;
    v_start timestamptz;
begin
    if p_limit < 1 or p_limit > 100000 or p_window_seconds < 1 or p_window_seconds > 86400 then
        raise exception 'invalid autonomous agent rate parameters';
    end if;

    select * into v_agent
      from auto_agents
     where id = p_agent and tenant_id = p_tenant
     for update;

    if not found then
        return jsonb_build_object('allowed', false, 'reason', 'agent_not_found');
    end if;

    select coalesce(frozen, false) into v_frozen
      from auto_agent_freeze
     where tenant_id = p_tenant;

    if coalesce(v_frozen, false) then
        return jsonb_build_object('allowed', false, 'reason', 'tenant_frozen');
    end if;

    if not v_agent.enabled or v_agent.status <> 'active' then
        return jsonb_build_object('allowed', false, 'reason', 'agent_inactive');
    end if;

    insert into auto_agent_rate(agent_id, window_start, action_count)
    values (p_agent, v_now, 0)
    on conflict (agent_id) do nothing;

    select action_count, window_start into v_count, v_start
      from auto_agent_rate
     where agent_id = p_agent
     for update;

    if v_start < v_now - make_interval(secs => p_window_seconds) then
        update auto_agent_rate
           set window_start = v_now, action_count = 0
         where agent_id = p_agent;
        v_count := 0;
    end if;

    if v_count >= p_limit then
        update auto_agents
           set actions_blocked = actions_blocked + 1, updated_at = v_now
         where id = p_agent;
        return jsonb_build_object(
            'allowed', false, 'reason', 'rate_limit',
            'action_count', v_count, 'limit', p_limit
        );
    end if;

    update auto_agent_rate
       set action_count = action_count + 1
     where agent_id = p_agent;

    update auto_agents
       set actions_total = actions_total + 1,
           last_action_at = v_now,
           updated_at = v_now
     where id = p_agent;

    return jsonb_build_object(
        'allowed', true,
        'action_count', v_count + 1,
        'limit', p_limit,
        'window_start', v_start
    );
end;
$$;

revoke all on function auto_agent_reserve_action(uuid, uuid, integer, integer) from public;
grant execute on function auto_agent_reserve_action(uuid, uuid, integer, integer) to service_role;

create or replace function auto_agent_is_frozen(p_tenant uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select coalesce(
        (select frozen from auto_agent_freeze where tenant_id = p_tenant),
        false
    );
$$;

revoke all on function auto_agent_is_frozen(uuid) from public;
grant execute on function auto_agent_is_frozen(uuid) to service_role;

create or replace function auto_agent_record_decision(p_row jsonb)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id uuid;
    v_tenant uuid;
    v_agent uuid;
begin
    v_tenant := nullif(p_row->>'tenant_id','')::uuid;
    v_agent := nullif(p_row->>'agent_id','')::uuid;

    if v_tenant is null or v_agent is null then
        raise exception 'tenant_id and agent_id are required';
    end if;

    if not exists (
        select 1 from auto_agents where id = v_agent and tenant_id = v_tenant
    ) then
        raise exception 'agent tenant binding invalid';
    end if;

    insert into auto_agent_decisions(
        tenant_id, agent_id, trigger_kind, trigger_id, detection_id, case_id,
        proposed_action, proposed_args, target_device, gates,
        llm_reasoning, llm_model, llm_tokens, outcome, block_reason,
        confidence, case_action_id, command_id, execution_ref
    )
    values (
        v_tenant, v_agent,
        coalesce(p_row->>'trigger_kind','detection'),
        coalesce(p_row->>'trigger_id','unknown'),
        nullif(p_row->>'detection_id','')::uuid,
        nullif(p_row->>'case_id','')::uuid,
        coalesce(p_row->>'proposed_action','none'),
        coalesce(p_row->'proposed_args','{}'::jsonb),
        nullif(p_row->>'target_device','')::uuid,
        coalesce(p_row->'gates','[]'::jsonb),
        p_row->>'llm_reasoning',
        p_row->>'llm_model',
        nullif(p_row->>'llm_tokens','')::integer,
        coalesce(p_row->>'outcome','failed'),
        p_row->>'block_reason',
        nullif(p_row->>'confidence','')::real,
        nullif(p_row->>'case_action_id','')::uuid,
        nullif(p_row->>'command_id','')::uuid,
        p_row->>'execution_ref'
    )
    returning id into v_id;

    return v_id;
end;
$$;

revoke all on function auto_agent_record_decision(jsonb) from public;
grant execute on function auto_agent_record_decision(jsonb) to service_role;
