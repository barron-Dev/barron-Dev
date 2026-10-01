-- Sentinel AI Agent Security control plane, migration 027.
-- Defensive controls for authorized tenant-owned LLM agents.
-- Content is hashed by default; previews are opt-in and bounded.

create table if not exists public.ai_agents (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete cascade,
    name text not null check (length(name) between 1 and 120), framework text, model text, description text,
    declared_tools text[] not null default '{}', data_scopes text[] not null default '{}',
    trust_level text not null default 'untrusted' check (trust_level in ('untrusted','limited','trusted','system')),
    status text not null default 'active' check (status in ('active','suspended','quarantined')),
    created_at timestamptz not null default now(), unique(id, tenant_id)
);
create index if not exists idx_ai_agents_tenant on public.ai_agents(tenant_id,status);

create table if not exists public.agent_actions (
    id bigserial primary key, tenant_id uuid not null references public.tenants(id) on delete cascade,
    agent_id uuid not null, trace_id uuid not null, parent_id bigint,
    kind text not null check (kind in ('prompt_in','prompt_out','tool_call','tool_result','memory_write','memory_read','agent_message','error')),
    tool_name text, content_hash text check (content_hash is null or content_hash ~ '^[0-9a-f]{64}$'),
    content_preview text check (content_preview is null or length(content_preview)<=500),
    risk_score real not null default 0 check (risk_score between 0 and 1), risk_reasons jsonb not null default '[]',
    blocked boolean not null default false, ts timestamptz not null default now(),
    foreign key(agent_id,tenant_id) references public.ai_agents(id,tenant_id) on delete cascade
);
create index if not exists idx_agent_actions_tenant on public.agent_actions(tenant_id,ts desc);
create index if not exists idx_agent_actions_agent on public.agent_actions(agent_id,ts desc);
create index if not exists idx_agent_actions_risky on public.agent_actions(tenant_id,risk_score desc) where risk_score>0.5;
create index if not exists idx_agent_actions_trace on public.agent_actions(trace_id);

create table if not exists public.prompt_injections (
    id bigserial primary key, tenant_id uuid not null references public.tenants(id) on delete cascade,
    agent_id uuid not null, action_id bigint references public.agent_actions(id) on delete set null,
    category text not null check (category in ('instruction_override','role_hijack','system_prompt_leak','tool_abuse','data_exfil','jailbreak','context_poison','indirect_injection','prompt_leak','encoding_evasion')),
    severity text not null default 'high' check (severity in ('low','medium','high','critical')),
    pattern text, snippet text check (snippet is null or length(snippet)<=500), blocked boolean not null default true, created_at timestamptz not null default now(),
    foreign key(agent_id,tenant_id) references public.ai_agents(id,tenant_id) on delete cascade
);
create index if not exists idx_prompt_injections_tenant on public.prompt_injections(tenant_id,created_at desc);

create table if not exists public.agent_trust (
    source_agent_id uuid not null, target_agent_id uuid not null, tenant_id uuid not null references public.tenants(id) on delete cascade,
    call_count integer not null default 0 check(call_count>=0), first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
    risk_score real not null default 0 check(risk_score between 0 and 1), primary key(source_agent_id,target_agent_id),
    foreign key(source_agent_id,tenant_id) references public.ai_agents(id,tenant_id) on delete cascade,
    foreign key(target_agent_id,tenant_id) references public.ai_agents(id,tenant_id) on delete cascade,
    check(source_agent_id<>target_agent_id)
);

create table if not exists public.agent_tool_policy (
    agent_id uuid not null references public.ai_agents(id) on delete cascade, tool_name text not null check(length(tool_name) between 1 and 128),
    allowed boolean not null default true, max_calls_per_minute integer not null default 60 check(max_calls_per_minute between 1 and 100000),
    requires_approval boolean not null default false, arg_constraints jsonb not null default '{}', primary key(agent_id,tool_name)
);

create table if not exists public.agent_memory (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete cascade, agent_id uuid not null,
    key text not null check(length(key) between 1 and 500), content_hash text not null check(content_hash ~ '^[0-9a-f]{64}$'), content_ref text,
    written_by text not null, source_trace_id uuid, verified boolean not null default false, created_at timestamptz not null default now(),
    unique(agent_id,key), foreign key(agent_id,tenant_id) references public.ai_agents(id,tenant_id) on delete cascade
);
create index if not exists idx_agent_memory_agent on public.agent_memory(agent_id,created_at desc);

create table if not exists public.agent_incidents (
    id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete cascade, agent_id uuid not null,
    trigger_action bigint references public.agent_actions(id) on delete set null, category text not null,
    severity text not null default 'high' check(severity in ('low','medium','high','critical')),
    action_taken text not null check(action_taken in ('blocked','suspended','quarantined','flagged','approved')),
    case_id uuid references public.crime_cases(id) on delete set null, details jsonb not null default '{}', created_at timestamptz not null default now(),
    foreign key(agent_id,tenant_id) references public.ai_agents(id,tenant_id) on delete cascade
);
create index if not exists idx_agent_incidents_tenant on public.agent_incidents(tenant_id,created_at desc);

alter table public.ai_agents enable row level security;
alter table public.agent_actions enable row level security;
alter table public.prompt_injections enable row level security;
alter table public.agent_trust enable row level security;
alter table public.agent_tool_policy enable row level security;
alter table public.agent_memory enable row level security;
alter table public.agent_incidents enable row level security;

create policy ai_agents_tenant_select on public.ai_agents for select to authenticated using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy agent_actions_tenant_select on public.agent_actions for select to authenticated using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy prompt_injections_tenant_select on public.prompt_injections for select to authenticated using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy agent_trust_tenant_select on public.agent_trust for select to authenticated using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy agent_tool_policy_tenant_select on public.agent_tool_policy for select to authenticated using(exists(select 1 from public.ai_agents a where a.id=agent_tool_policy.agent_id and a.tenant_id=(auth.jwt()->>'tenant_id')::uuid));
create policy agent_memory_tenant_select on public.agent_memory for select to authenticated using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);
create policy agent_incidents_tenant_select on public.agent_incidents for select to authenticated using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

revoke all on public.ai_agents,public.agent_actions,public.prompt_injections,public.agent_trust,public.agent_tool_policy,public.agent_memory,public.agent_incidents from anon,authenticated;
grant select on public.ai_agents,public.agent_actions,public.prompt_injections,public.agent_trust,public.agent_tool_policy,public.agent_memory,public.agent_incidents to authenticated;
