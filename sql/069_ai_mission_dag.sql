-- Executable, bounded Mission DAG definitions.
create table if not exists public.ai_missions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    name text not null,
    version integer not null check (version > 0),
    status text not null default 'draft' check (status in ('draft','active','retired')),
    definition jsonb not null,
    compiled_hash text not null check (compiled_hash ~ '^[0-9a-f]{64}$'),
    is_dag boolean not null default false,
    max_nodes integer not null check (max_nodes between 1 and 256),
    max_edges integer not null check (max_edges between 0 and 1024),
    created_at timestamptz not null default now(),
    unique (tenant_id, name, version)
);
create index if not exists idx_ai_missions_active on public.ai_missions(tenant_id, name, version desc) where status='active';
alter table public.ai_missions enable row level security;
revoke all on public.ai_missions from public, anon, authenticated;

-- Mission bindings on durable response actions/commands.
alter table public.case_actions
  add column if not exists ai_mission_id text,
  add column if not exists ai_mission_version integer,
  add column if not exists ai_mission_hash text;
alter table public.commands
  add column if not exists ai_mission_id text,
  add column if not exists ai_mission_version integer,
  add column if not exists ai_mission_hash text;
create index if not exists idx_case_actions_ai_mission on public.case_actions(tenant_id, ai_mission_id, ai_mission_version) where ai_mission_id is not null;
create index if not exists idx_commands_ai_mission on public.commands(tenant_id, ai_mission_id, ai_mission_version) where ai_mission_id is not null;
