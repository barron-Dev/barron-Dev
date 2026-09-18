-- Runtime alignment for the unified response layer.
-- Keeps production schema synchronized with the canonical response orchestrator.
alter table auto_case_rules
    add column if not exists default_playbook_id uuid references playbooks(id) on delete set null,
    add column if not exists auto_actions jsonb not null default '[]'::jsonb,
    add column if not exists dry_run boolean not null default false,
    add column if not exists blast_radius_limit integer not null default 10;

create table if not exists case_actions (
    id uuid primary key default gen_random_uuid(),
    case_id uuid not null references crime_cases(id) on delete cascade,
    tenant_id uuid not null references tenants(id) on delete cascade,
    device_id uuid references devices(id) on delete set null,
    action text not null,
    args jsonb not null default '{}'::jsonb,
    status text not null default 'pending_approval' check (status in ('pending_approval','approved','rejected','dispatched','executing','success','failed','rolled_back')),
    command_id uuid references commands(id) on delete set null,
    issued_by text not null,
    initiated_by_rule uuid references auto_case_rules(id) on delete set null,
    signature text,
    signer_kid text,
    approved_by uuid references auth.users(id) on delete set null,
    approved_at timestamptz,
    rejected_by uuid references auth.users(id) on delete set null,
    rejected_at timestamptz,
    rejection_reason text,
    rollback_args jsonb,
    rollback_case_action_id uuid references case_actions(id) on delete set null,
    created_at timestamptz not null default now(),
    dispatched_at timestamptz,
    executed_at timestamptz,
    result jsonb,
    error text
);
create index if not exists idx_case_actions_case on case_actions(case_id, created_at desc);
create index if not exists idx_case_actions_tenant_status on case_actions(tenant_id, status);
create index if not exists idx_case_actions_pending on case_actions(tenant_id) where status = 'pending_approval';
alter table case_actions enable row level security;
drop policy if exists case_actions_tenant on case_actions;
create policy case_actions_tenant on case_actions for all to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
    with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists rule_blast_log (
    id bigserial primary key,
    rule_id uuid not null references auto_case_rules(id) on delete cascade,
    tenant_id uuid not null references tenants(id) on delete cascade,
    device_id uuid not null references devices(id) on delete cascade,
    case_id uuid references crime_cases(id) on delete set null,
    ts timestamptz not null default now()
);
create index if not exists idx_blast_log_rule_ts on rule_blast_log(rule_id, ts desc);
alter table rule_blast_log enable row level security;
drop policy if exists rule_blast_log_tenant on rule_blast_log;
create policy rule_blast_log_tenant on rule_blast_log for all to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
    with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists report_templates (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    agency text not null,
    name text not null,
    description text,
    format text not null check (format in ('pdf','json','stix2.1','csv')),
    template jsonb not null,
    active boolean not null default true,
    created_at timestamptz not null default now()
);
alter table report_templates enable row level security;
drop policy if exists report_templates_read on report_templates;
create policy report_templates_read on report_templates for select to authenticated
    using (tenant_id is null or tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create or replace function check_blast_radius(p_rule_id uuid, p_limit integer, p_window_minutes integer default 60)
returns boolean language plpgsql stable security definer set search_path = public as $$
declare v_count integer;
begin
    if p_limit < 1 or p_window_minutes < 1 then return false; end if;
    select count(distinct device_id) into v_count from rule_blast_log
    where rule_id = p_rule_id and ts >= now() - (p_window_minutes || ' minutes')::interval;
    return v_count < p_limit;
end;
$$;
revoke all on function check_blast_radius(uuid, integer, integer) from public;
grant execute on function check_blast_radius(uuid, integer, integer) to service_role;
