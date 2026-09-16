-- Sentinel Investigation Control Plane, migration 022.
-- This subsystem orchestrates authorized remote-forensics providers and isolated
-- investigation workstations. It does not execute arbitrary code on third-party endpoints.

create table if not exists investigation_sessions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    case_id uuid references crime_cases(id) on delete set null,
    created_by uuid references auth.users(id) on delete set null,
    purpose text not null check (length(purpose) between 1 and 500),
    authorization_ref text not null check (length(authorization_ref) between 1 and 500),
    status text not null default 'requested' check (status in ('requested','approved','running','completed','cancelled','failed')),
    provider text not null check (length(provider) between 1 and 120),
    provider_session_id text,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index if not exists idx_investigation_sessions_tenant on investigation_sessions(tenant_id, created_at desc);
create index if not exists idx_investigation_sessions_case on investigation_sessions(case_id, created_at desc);

create table if not exists investigation_evidence (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    session_id uuid not null references investigation_sessions(id) on delete cascade,
    evidence_type text not null check (evidence_type in ('network','dns','process','file','browser','screenshot','indicator','provider_record','other')),
    sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
    object_ref text not null,
    collected_at timestamptz not null,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    unique(session_id, sha256, object_ref)
);
create index if not exists idx_investigation_evidence_session on investigation_evidence(session_id, collected_at desc);

create table if not exists investigation_events (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    session_id uuid not null references investigation_sessions(id) on delete cascade,
    event_type text not null,
    event_at timestamptz not null default now(),
    actor text,
    payload jsonb not null default '{}'::jsonb
);
create index if not exists idx_investigation_events_session on investigation_events(session_id, event_at desc);

alter table investigation_sessions enable row level security;
alter table investigation_evidence enable row level security;
alter table investigation_events enable row level security;

create policy investigation_sessions_tenant_select on investigation_sessions for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));
create policy investigation_evidence_tenant_select on investigation_evidence for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));
create policy investigation_events_tenant_select on investigation_events for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on investigation_sessions, investigation_evidence, investigation_events from anon, authenticated;
grant select on investigation_sessions, investigation_evidence, investigation_events to authenticated;

-- Mutations remain service-role only. Authorization is represented by an
-- explicit authorization_ref and enforced by the application/provider boundary.
revoke all on investigation_sessions, investigation_evidence, investigation_events from public;
