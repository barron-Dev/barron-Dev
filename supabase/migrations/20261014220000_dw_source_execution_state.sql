begin;

-- One row per configured Dark Web provider. This is execution state, not a
-- count of channels, endpoints, findings, or total public sources.
create table if not exists public.dw_source_execution_state (
    source_id text primary key references public.dw_sources(id) on delete cascade,
    last_status text not null,
    last_execution_at timestamptz not null default now(),
    last_execution_pulled boolean not null default false,
    execution_count bigint not null default 0 check (execution_count >= 0),
    successful_pull_count bigint not null default 0 check (successful_pull_count >= 0),
    failed_execution_count bigint not null default 0 check (failed_execution_count >= 0),
    last_error text,
    updated_at timestamptz not null default now()
);

create index if not exists dw_source_execution_state_recent_idx
    on public.dw_source_execution_state (last_execution_at desc);

alter table public.dw_source_execution_state enable row level security;
revoke all on table public.dw_source_execution_state from public, anon, authenticated;
grant select, insert, update, delete on table public.dw_source_execution_state to service_role;

commit;
