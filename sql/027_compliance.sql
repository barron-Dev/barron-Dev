-- Sentinel Compliance Automation, migration 027.
-- Evidence packs are structured, hash-addressed audit artifacts. This is an
-- evidence automation layer; it does not itself certify legal compliance.

create table if not exists public.compliance_controls (
    id uuid primary key default gen_random_uuid(),
    framework text not null check (framework in ('soc2','iso27001','gdpr','hipaa')),
    control_code text not null,
    title text not null,
    description text not null,
    evidence_sources text[] not null default '{}',
    created_at timestamptz not null default now(),
    unique(framework, control_code)
);
create index if not exists compliance_controls_framework_idx on public.compliance_controls(framework, control_code);

create table if not exists public.compliance_evidence (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    framework text not null check (framework in ('soc2','iso27001','gdpr','hipaa')),
    control_id uuid not null references public.compliance_controls(id) on delete restrict,
    title text not null,
    evidence_type text not null check (evidence_type in ('generated','configuration','audit','telemetry','document','external')),
    source_ref text,
    object_ref text,
    sha256 text,
    collected_at timestamptz not null default now(),
    valid_from timestamptz,
    valid_until timestamptz,
    metadata jsonb not null default '{}'::jsonb,
    collected_by uuid references auth.users(id) on delete set null
);
create index if not exists compliance_evidence_tenant_framework_idx on public.compliance_evidence(tenant_id, framework, collected_at desc);
create index if not exists compliance_evidence_control_idx on public.compliance_evidence(control_id, tenant_id);

create table if not exists public.compliance_runs (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    framework text not null check (framework in ('soc2','iso27001','gdpr','hipaa')),
    status text not null default 'running' check (status in ('running','completed','failed')),
    period_start timestamptz not null,
    period_end timestamptz not null,
    controls_total integer not null default 0 check (controls_total >= 0),
    controls_with_evidence integer not null default 0 check (controls_with_evidence >= 0),
    evidence_count integer not null default 0 check (evidence_count >= 0),
    error text,
    started_at timestamptz not null default now(),
    completed_at timestamptz,
    created_by uuid references auth.users(id) on delete set null,
    check (period_end > period_start)
);
create index if not exists compliance_runs_tenant_idx on public.compliance_runs(tenant_id, started_at desc);

create table if not exists public.compliance_packs (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    run_id uuid not null references public.compliance_runs(id) on delete cascade,
    framework text not null check (framework in ('soc2','iso27001','gdpr','hipaa')),
    period_start timestamptz not null,
    period_end timestamptz not null,
    status text not null default 'ready' check (status in ('ready','failed')),
    object_ref text,
    sha256 text,
    generated_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb
);
create index if not exists compliance_packs_tenant_idx on public.compliance_packs(tenant_id, generated_at desc);

alter table public.compliance_controls enable row level security;
alter table public.compliance_evidence enable row level security;
alter table public.compliance_runs enable row level security;
alter table public.compliance_packs enable row level security;

drop policy if exists compliance_controls_select on public.compliance_controls;
create policy compliance_controls_select on public.compliance_controls for select to authenticated using (true);
drop policy if exists compliance_evidence_select on public.compliance_evidence;
create policy compliance_evidence_select on public.compliance_evidence for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists compliance_runs_select on public.compliance_runs;
create policy compliance_runs_select on public.compliance_runs for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
drop policy if exists compliance_packs_select on public.compliance_packs;
create policy compliance_packs_select on public.compliance_packs for select to authenticated using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create or replace function public.compliance_evidence_append_only()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'compliance evidence is append-only';
end;
$$;
drop trigger if exists compliance_evidence_immutable on public.compliance_evidence;
create trigger compliance_evidence_immutable
before update or delete on public.compliance_evidence
for each row execute function public.compliance_evidence_append_only();
revoke all on function public.compliance_evidence_append_only() from public, anon, authenticated;

revoke all on public.compliance_controls from anon, authenticated;
grant select on public.compliance_controls to authenticated;
revoke all on public.compliance_evidence, public.compliance_runs, public.compliance_packs from anon, authenticated;
grant select on public.compliance_evidence, public.compliance_runs, public.compliance_packs to authenticated;
grant all on public.compliance_controls, public.compliance_evidence, public.compliance_runs, public.compliance_packs to service_role;

insert into public.compliance_controls(framework, control_code, title, description, evidence_sources) values
('soc2','CC6.1','Logical access controls','Access to systems and data is restricted to authorized identities.','{developer_apps,audit_log}'),
('soc2','CC6.6','Security boundaries','Logical access and security boundaries protect systems and information.','{data_trust,detections,devices}'),
('soc2','CC7.2','Monitoring','Security events are detected, analyzed, and acted upon.','{detections,agent_actions,investigation_events}'),
('soc2','CC8.1','Change management','Changes are authorized, tested, and traceable.','{audit_log,commands,case_actions}'),
('iso27001','A.5.15','Access control','Access to information and systems is controlled according to business and security requirements.','{developer_apps,audit_log}'),
('iso27001','A.8.15','Logging','Relevant activities are logged and protected.','{audit_log,investigation_events,hunt_runs}'),
('iso27001','A.8.16','Monitoring activities','Systems are monitored for anomalous behavior and security events.','{detections,agent_actions,hunt_runs}'),
('gdpr','Art.5','Principles relating to processing','Processing is documented and aligned with data protection principles.','{regions,data_trust,audit_log}'),
('gdpr','Art.32','Security of processing','Appropriate technical and organizational security measures are evidenced.','{devices,data_trust,recovery,detections}'),
('hipaa','164.308(a)(1)','Security management process','Risk analysis and security controls are maintained.','{detections,audit_log,compliance_runs}'),
('hipaa','164.312(b)','Audit controls','Mechanisms record and examine activity in systems containing regulated information.','{audit_log,hunt_runs,investigation_events}')
on conflict (framework, control_code) do update set title = excluded.title, description = excluded.description, evidence_sources = excluded.evidence_sources;
