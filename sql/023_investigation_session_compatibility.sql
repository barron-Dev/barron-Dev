-- Sentinel Investigation session compatibility, migration 023.
-- Reconciles the existing investigation control-plane schema with the
-- application service contract without replacing existing investigation data.

create table if not exists investigation_sessions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    case_id uuid references crime_cases(id) on delete set null,
    created_by uuid references auth.users(id) on delete set null,
    purpose text not null,
    authorization_ref text not null,
    status text not null default 'requested',
    provider text not null,
    provider_session_id text,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_investigation_sessions_tenant
    on investigation_sessions(tenant_id, created_at desc);
create index if not exists idx_investigation_sessions_case
    on investigation_sessions(case_id, created_at desc);

create table if not exists investigation_events (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    session_id uuid not null references investigation_sessions(id) on delete cascade,
    event_type text not null,
    event_at timestamptz not null default now(),
    actor text,
    payload jsonb not null default '{}'::jsonb
);

create index if not exists idx_investigation_events_session
    on investigation_events(session_id, event_at desc);

alter table investigation_evidence
    add column if not exists session_id uuid,
    add column if not exists object_ref text,
    add column if not exists collected_at timestamptz,
    add column if not exists created_at timestamptz not null default now();

update investigation_evidence
   set collected_at = coalesce(collected_at, observed_at, now())
 where collected_at is null;

update investigation_evidence
   set object_ref = coalesce(object_ref, object_path)
 where object_ref is null;

alter table investigation_evidence
    alter column collected_at set not null,
    alter column object_ref set not null;

alter table investigation_evidence
    drop constraint if exists investigation_evidence_session_fk;

alter table investigation_evidence
    add constraint investigation_evidence_session_fk
    foreign key (session_id) references investigation_sessions(id) on delete cascade;

create index if not exists idx_investigation_evidence_session
    on investigation_evidence(session_id, collected_at desc);

alter table investigation_sessions enable row level security;
alter table investigation_events enable row level security;
alter table investigation_evidence enable row level security;

drop policy if exists investigation_sessions_tenant_select on investigation_sessions;
create policy investigation_sessions_tenant_select
    on investigation_sessions for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists investigation_events_tenant_select on investigation_events;
create policy investigation_events_tenant_select
    on investigation_events for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists investigation_evidence_tenant_select on investigation_evidence;
create policy investigation_evidence_tenant_select
    on investigation_evidence for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on investigation_sessions, investigation_events, investigation_evidence from anon, authenticated;
grant select on investigation_sessions, investigation_events, investigation_evidence to authenticated;
