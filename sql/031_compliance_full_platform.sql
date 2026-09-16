-- Sentinel Compliance Platform, migration 031.
-- Extends the existing compliance schema; does not replace prior migrations.
-- These tables support readiness, evidence operations, auditor collaboration,
-- remediation, vendor risk and a public trust center. They do not issue an
-- independent SOC attestation or auditor opinion.

create table if not exists public.audit_engagements (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    framework_id text not null references public.compliance_frameworks(id) on delete restrict,
    auditor_firm text not null check (length(trim(auditor_firm)) between 1 and 200),
    auditor_lead text not null check (length(trim(auditor_lead)) between 1 and 200),
    auditor_email text not null check (length(trim(auditor_email)) between 3 and 320),
    period_start timestamptz not null,
    period_end timestamptz not null,
    type text not null check (type in ('type1','type2')),
    status text not null default 'planning' check (status in ('planning','fieldwork','review','issued','closed')),
    report_url text,
    report_sha256 text,
    issued_at timestamptz,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    check (period_end > period_start),
    check (issued_at is null or issued_at >= period_end)
);
create index if not exists audit_engagements_tenant_idx on public.audit_engagements(tenant_id, status, period_start desc);

create table if not exists public.auditor_access (
    id uuid primary key default gen_random_uuid(),
    engagement_id uuid not null references public.audit_engagements(id) on delete cascade,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    token_hash text not null unique,
    scopes text[] not null default array['evidence:read','controls:read','queries:read','queries:ask'],
    expires_at timestamptz not null,
    revoked_at timestamptz,
    last_used_at timestamptz,
    last_used_ip inet,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    check (expires_at > created_at)
);
create index if not exists auditor_access_engagement_idx on public.auditor_access(engagement_id, expires_at);
create index if not exists auditor_access_active_idx on public.auditor_access(token_hash) where revoked_at is null;

create table if not exists public.auditor_queries (
    id uuid primary key default gen_random_uuid(),
    engagement_id uuid not null references public.audit_engagements(id) on delete cascade,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    control_id uuid references public.compliance_controls(id) on delete set null,
    question text not null check (length(trim(question)) between 1 and 10000),
    answer text,
    status text not null default 'open' check (status in ('open','answered','accepted','rejected')),
    asked_by text not null check (length(trim(asked_by)) between 1 and 320),
    answered_by uuid references auth.users(id) on delete set null,
    answered_at timestamptz,
    attachments jsonb not null default '[]'::jsonb check (jsonb_typeof(attachments) = 'array'),
    created_at timestamptz not null default now()
);
create index if not exists auditor_queries_engagement_idx on public.auditor_queries(engagement_id, status, created_at desc);

create table if not exists public.evidence_items (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    control_id uuid not null references public.compliance_controls(id) on delete restrict,
    check_key text not null,
    source text not null,
    collected_at timestamptz not null default now(),
    valid_until timestamptz,
    payload jsonb not null default '{}'::jsonb,
    payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
    status text not null default 'active' check (status in ('active','stale','superseded','rejected')),
    provenance jsonb not null default '{}'::jsonb
);
create index if not exists evidence_items_control_idx on public.evidence_items(tenant_id, control_id, collected_at desc);
create index if not exists evidence_items_stale_idx on public.evidence_items(tenant_id, valid_until) where status = 'active' and valid_until is not null;

create table if not exists public.control_owners (
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    control_id uuid not null references public.compliance_controls(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role text not null default 'owner' check (role in ('owner','backup','reviewer')),
    assigned_at timestamptz not null default now(),
    primary key (tenant_id, control_id, user_id)
);

create table if not exists public.control_exceptions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    control_id uuid not null references public.compliance_controls(id) on delete restrict,
    reason text not null,
    compensating text,
    remediation_due date,
    status text not null default 'open' check (status in ('open','remediating','resolved','accepted')),
    approved_by uuid references auth.users(id) on delete set null,
    approved_at timestamptz,
    created_at timestamptz not null default now(),
    check ((status in ('accepted','resolved') and approved_by is not null and approved_at is not null) or status in ('open','remediating'))
);
create index if not exists control_exceptions_tenant_idx on public.control_exceptions(tenant_id, status, remediation_due);

create table if not exists public.remediation_tasks (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    control_id uuid references public.compliance_controls(id) on delete set null,
    title text not null check (length(trim(title)) between 1 and 500),
    description text,
    severity text not null default 'medium' check (severity in ('low','medium','high','critical')),
    status text not null default 'backlog' check (status in ('backlog','todo','in_progress','review','done')),
    assignee uuid references auth.users(id) on delete set null,
    due_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz not null default now(),
    check ((status = 'done' and completed_at is not null) or status <> 'done')
);
create index if not exists remediation_tasks_tenant_idx on public.remediation_tasks(tenant_id, status, severity, due_at);

create table if not exists public.vendors (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    name text not null check (length(trim(name)) between 1 and 200),
    category text not null check (category in ('cloud','saas','contractor','hardware','other')),
    criticality text not null default 'medium' check (criticality in ('low','medium','high','critical')),
    data_access text[] not null default '{}',
    soc2 boolean not null default false,
    iso27001 boolean not null default false,
    hipaa boolean not null default false,
    gdpr boolean not null default false,
    pci boolean not null default false,
    last_review_at timestamptz,
    next_review_at timestamptz,
    report_urls jsonb not null default '[]'::jsonb check (jsonb_typeof(report_urls) = 'array'),
    notes text,
    status text not null default 'active' check (status in ('active','under_review','offboarding','terminated')),
    created_at timestamptz not null default now()
);
create index if not exists vendors_tenant_idx on public.vendors(tenant_id, criticality, status);

create table if not exists public.trust_center (
    tenant_id uuid primary key references public.tenants(id) on delete cascade,
    slug text not null unique check (slug ~ '^[a-z0-9-]{3,60}$'),
    published boolean not null default false,
    company_name text,
    logo_url text,
    description text,
    frameworks text[] not null default array['soc2'],
    security_email text,
    security_phone text,
    updated_at timestamptz not null default now()
);

-- Auditor access telemetry is deliberately separate from the evidence corpus.
create table if not exists public.auditor_access_events (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    engagement_id uuid not null references public.audit_engagements(id) on delete cascade,
    access_id uuid not null references public.auditor_access(id) on delete cascade,
    event_type text not null check (event_type in ('authenticated','evidence_read','query_read','query_created','expired','revoked')),
    occurred_at timestamptz not null default now(),
    ip inet,
    metadata jsonb not null default '{}'::jsonb
);
create index if not exists auditor_access_events_engagement_idx on public.auditor_access_events(engagement_id, occurred_at desc);

-- Tenant isolation. Public trust-center reads are limited to published rows.
alter table public.audit_engagements enable row level security;
alter table public.auditor_access enable row level security;
alter table public.auditor_queries enable row level security;
alter table public.evidence_items enable row level security;
alter table public.control_owners enable row level security;
alter table public.control_exceptions enable row level security;
alter table public.remediation_tasks enable row level security;
alter table public.vendors enable row level security;
alter table public.trust_center enable row level security;
alter table public.auditor_access_events enable row level security;

create policy audit_engagements_tenant_select on public.audit_engagements for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy auditor_access_tenant_select on public.auditor_access for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy auditor_queries_tenant_select on public.auditor_queries for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy auditor_queries_tenant_insert on public.auditor_queries for insert to authenticated with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy evidence_items_tenant_select on public.evidence_items for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy control_owners_tenant_select on public.control_owners for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy control_exceptions_tenant_select on public.control_exceptions for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy remediation_tasks_tenant_select on public.remediation_tasks for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy vendors_tenant_select on public.vendors for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy trust_center_public_select on public.trust_center for select to anon, authenticated using (published = true);
create policy trust_center_tenant_select on public.trust_center for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
create policy auditor_access_events_tenant_select on public.auditor_access_events for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

-- Writes are service-role mediated by the application. No Data API mutation surface.
revoke insert, update, delete on public.audit_engagements, public.auditor_access, public.auditor_queries,
    public.evidence_items, public.control_owners, public.control_exceptions, public.remediation_tasks,
    public.vendors, public.trust_center, public.auditor_access_events from anon, authenticated;

create or replace function public.mark_compliance_evidence_stale()
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare v_count integer;
begin
    update public.evidence_items
       set status = 'stale'
     where status = 'active'
       and valid_until is not null
       and valid_until <= now();
    get diagnostics v_count = row_count;
    return v_count;
end;
$$;
revoke all on function public.mark_compliance_evidence_stale() from public, anon, authenticated;
grant execute on function public.mark_compliance_evidence_stale() to service_role;

create or replace function public.compliance_assurance_immutable()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
    raise exception 'compliance assurance records are append-only';
end;
$$;

drop trigger if exists evidence_items_immutable on public.evidence_items;
create trigger evidence_items_immutable before update or delete on public.evidence_items for each row execute function public.compliance_assurance_immutable();
revoke all on function public.compliance_assurance_immutable() from public, anon, authenticated;
grant execute on function public.compliance_assurance_immutable() to service_role;
