-- Real Dark Web source-run progress. Values are written by the live scheduler only.
create table if not exists public.dw_source_runs (
    id uuid primary key default gen_random_uuid(),
    source_id text not null references public.dw_sources(id) on delete cascade,
    target_label text,
    process_steps jsonb not null default '[]'::jsonb check (jsonb_typeof(process_steps) = 'array'),
    status text not null default 'running' check (status in ('running','ok','degraded','failed','cancelled')),
    stage text not null default 'connecting_to_source',
    progress_percent integer not null default 0 check (progress_percent between 0 and 100),
    discovered_count integer not null default 0 check (discovered_count >= 0),
    processed_count integer not null default 0 check (processed_count >= 0),
    matched_count integer not null default 0 check (matched_count >= 0),
    alert_count integer not null default 0 check (alert_count >= 0),
    error_count integer not null default 0 check (error_count >= 0),
    detail text,
    started_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz
);
create index if not exists dw_source_runs_recent_idx on public.dw_source_runs (source_id, started_at desc);
create index if not exists dw_source_runs_started_idx on public.dw_source_runs (started_at desc);
alter table public.dw_source_runs enable row level security;
revoke all on public.dw_source_runs from anon, authenticated;
grant select, insert, update on public.dw_source_runs to service_role;
