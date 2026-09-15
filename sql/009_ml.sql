-- Sentinel ML labels, training runs, and model registry.
-- Service-side training uses the service role; tenant-facing access remains RLS-scoped.

create table if not exists labels (
    id              uuid primary key default gen_random_uuid(),
    tenant_id       uuid not null references tenants(id) on delete cascade,
    event_id        uuid not null,
    detection_id    uuid references detections(id) on delete set null,
    label           int not null check (label in (0, 1)),
    source          text not null check (source in ('analyst', 'auto', 'feedback')),
    confidence      real not null default 1.0 check (confidence between 0 and 1),
    labeled_by      uuid references auth.users(id) on delete set null,
    note            text,
    created_at      timestamptz not null default now(),
    unique (event_id, source)
);

create index if not exists idx_labels_tenant on labels(tenant_id, created_at desc);
create index if not exists idx_labels_event on labels(event_id);

alter table labels enable row level security;
drop policy if exists labels_tenant_select on labels;
create policy labels_tenant_select on labels
    for select to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

drop policy if exists labels_tenant_insert on labels;
create policy labels_tenant_insert on labels
    for insert to authenticated
    with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

drop policy if exists labels_tenant_update on labels;
create policy labels_tenant_update on labels
    for update to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
    with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists training_runs (
    id              uuid primary key default gen_random_uuid(),
    tenant_id       uuid references tenants(id) on delete cascade,
    status          text not null default 'running'
                    check (status in ('running', 'success', 'failed')),
    algorithm       text not null,
    hyperparams     jsonb not null default '{}'::jsonb,
    n_samples       int,
    n_positive      int,
    n_negative      int,
    metrics         jsonb not null default '{}'::jsonb,
    artifact_path   text,
    error           text,
    started_at      timestamptz not null default now(),
    ended_at        timestamptz
);

create index if not exists idx_training_runs_tenant
    on training_runs(tenant_id, started_at desc);

alter table training_runs enable row level security;
drop policy if exists training_runs_tenant_select on training_runs;
create policy training_runs_tenant_select on training_runs
    for select to authenticated
    using (tenant_id is null or tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists models (
    id              uuid primary key default gen_random_uuid(),
    tenant_id       uuid references tenants(id) on delete cascade,
    version         int not null,
    algorithm       text not null,
    artifact_path   text not null,
    artifact_sha256 text not null check (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    training_run_id uuid references training_runs(id) on delete set null,
    active          boolean not null default false,
    metrics         jsonb not null default '{}'::jsonb,
    feature_names   text[] not null,
    created_at      timestamptz not null default now(),
    unique (tenant_id, version)
);

create unique index if not exists idx_models_one_active_per_tenant
    on models ((coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)))
    where active = true;

create index if not exists idx_models_tenant_version
    on models(tenant_id, version desc);

alter table models enable row level security;
drop policy if exists models_read on models;
create policy models_read on models
    for select to authenticated
    using (tenant_id is null or tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

-- Training artifacts are private. Service-role jobs perform uploads/downloads.
insert into storage.buckets (id, name, public)
values ('models', 'models', false)
on conflict (id) do nothing;

-- New public-schema tables are not automatically exposed by newer Supabase projects.
-- Explicit grants keep Data API access intentional; RLS remains the row-level boundary.
grant select on labels, training_runs, models to authenticated;
grant insert, update on labels to authenticated;
