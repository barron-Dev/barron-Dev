-- 081_workforce_identity_authority.sql
-- Workforce Identity & Internal Authority Foundation.
-- GitHub-only foundation: do not apply to production without explicit authorization.
-- Security model:
--   employee identity != role != permission != scope != session != task authority.
--   Workforce data is private-schema and server-only.
--   Authorization is fail-closed and must be evaluated by the application before work actions.
--   Customer/tenant scope is explicit; knowing a tenant UUID is never sufficient.

create schema if not exists workforce;

create type workforce.employee_status as enum (
  'pending',
  'active',
  'suspended',
  'terminated'
);

create type workforce.assignment_status as enum (
  'active',
  'expired',
  'revoked'
);

create type workforce.scope_type as enum (
  'global',
  'tenant',
  'project',
  'resource'
);

create type workforce.lifecycle_event_type as enum (
  'hired',
  'activated',
  'suspended',
  'role_changed',
  'scope_changed',
  'terminated',
  'offboarding_started',
  'offboarding_completed'
);

create type workforce.offboarding_status as enum (
  'queued',
  'running',
  'completed',
  'failed'
);

create table workforce.departments (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  name text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (length(trim(code)) > 0),
  check (length(trim(name)) > 0)
);

create table workforce.employees (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete restrict,
  employee_number text unique,
  legal_name text,
  display_name text,
  department_id uuid references workforce.departments(id) on delete restrict,
  status workforce.employee_status not null default 'pending',
  hired_at timestamptz,
  terminated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (status = 'terminated' and terminated_at is not null)
    or status <> 'terminated'
  )
);

create table workforce.roles (
  id uuid primary key default gen_random_uuid(),
  role_key text not null unique,
  name text not null,
  description text,
  system_role boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table workforce.permissions (
  id uuid primary key default gen_random_uuid(),
  permission_key text not null unique,
  name text not null,
  description text,
  scope_required boolean not null default true,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table workforce.role_permissions (
  role_id uuid not null references workforce.roles(id) on delete cascade,
  permission_id uuid not null references workforce.permissions(id) on delete cascade,
  granted_at timestamptz not null default now(),
  primary key (role_id, permission_id)
);

create table workforce.employee_roles (
  employee_id uuid not null references workforce.employees(id) on delete cascade,
  role_id uuid not null references workforce.roles(id) on delete restrict,
  status workforce.assignment_status not null default 'active',
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  assigned_by uuid references workforce.employees(id) on delete restrict,
  created_at timestamptz not null default now(),
  primary key (employee_id, role_id),
  check (valid_until is null or valid_until > valid_from)
);

create table workforce.employee_scopes (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references workforce.employees(id) on delete cascade,
  scope_type workforce.scope_type not null,
  scope_id uuid,
  status workforce.assignment_status not null default 'active',
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  granted_by uuid references workforce.employees(id) on delete restrict,
  created_at timestamptz not null default now(),
  check (
    (scope_type = 'global' and scope_id is null)
    or (scope_type <> 'global' and scope_id is not null)
  ),
  check (valid_until is null or valid_until > valid_from),
  unique (employee_id, scope_type, scope_id)
);

create table workforce.authority_limits (
  employee_id uuid primary key references workforce.employees(id) on delete cascade,
  max_concurrent_tasks integer not null default 5 check (max_concurrent_tasks > 0),
  max_daily_tasks integer not null default 50 check (max_daily_tasks > 0),
  max_pending_approvals integer not null default 0 check (max_pending_approvals >= 0),
  max_approval_value numeric(20,2),
  updated_at timestamptz not null default now(),
  check (max_approval_value is null or max_approval_value >= 0)
);

create table workforce.sessions (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references workforce.employees(id) on delete cascade,
  auth_session_id uuid unique,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text,
  check (expires_at > issued_at),
  check (revoked_at is null or revoked_at >= issued_at)
);

create table workforce.lifecycle_events (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references workforce.employees(id) on delete cascade,
  event_type workforce.lifecycle_event_type not null,
  actor_employee_id uuid references workforce.employees(id) on delete restrict,
  reason text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table workforce.offboarding_jobs (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references workforce.employees(id) on delete restrict,
  status workforce.offboarding_status not null default 'queued',
  requested_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  last_error text,
  attempt_count integer not null default 0 check (attempt_count >= 0),
  unique (employee_id, status)
);

create table workforce.offboarding_actions (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references workforce.offboarding_jobs(id) on delete cascade,
  action_key text not null,
  status text not null default 'pending',
  completed_at timestamptz,
  error_text text,
  created_at timestamptz not null default now(),
  unique (job_id, action_key),
  check (status in ('pending','completed','failed'))
);

create index employee_roles_active_idx
  on workforce.employee_roles(employee_id, status, valid_from, valid_until);

create index employee_scopes_lookup_idx
  on workforce.employee_scopes(employee_id, scope_type, scope_id, status, valid_from, valid_until);

create index workforce_sessions_active_idx
  on workforce.sessions(employee_id, revoked_at, expires_at);

create index lifecycle_events_employee_created_idx
  on workforce.lifecycle_events(employee_id, created_at desc);

create index offboarding_jobs_status_idx
  on workforce.offboarding_jobs(status, requested_at);

create or replace function workforce.touch_updated_at()
returns trigger
language plpgsql
set search_path = workforce, pg_catalog
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create trigger departments_touch_updated_at
before update on workforce.departments
for each row execute function workforce.touch_updated_at();

create trigger employees_touch_updated_at
before update on workforce.employees
for each row execute function workforce.touch_updated_at();

create trigger roles_touch_updated_at
before update on workforce.roles
for each row execute function workforce.touch_updated_at();

create trigger permissions_touch_updated_at
before update on workforce.permissions
for each row execute function workforce.touch_updated_at();

create or replace function workforce.queue_offboarding()
returns trigger
language plpgsql
security definer
set search_path = workforce, pg_catalog
as $$
begin
  if new.status = 'terminated'
     and old.status is distinct from 'terminated' then

    update workforce.sessions
       set revoked_at = coalesce(revoked_at, now()),
           revoke_reason = coalesce(revoke_reason, 'employee_terminated')
     where employee_id = new.id
       and revoked_at is null;

    update workforce.employee_roles
       set status = 'revoked',
           valid_until = least(coalesce(valid_until, now()), now())
     where employee_id = new.id
       and status = 'active';

    insert into workforce.offboarding_jobs (employee_id)
    values (new.id)
    on conflict do nothing;

    insert into workforce.lifecycle_events (
      employee_id,
      event_type,
      reason
    )
    values (
      new.id,
      'offboarding_started',
      'employee_terminated'
    );
  end if;

  return new;
end;
$$;

create trigger employees_queue_offboarding
after update of status on workforce.employees
for each row execute function workforce.queue_offboarding();

create or replace function workforce.authorize(
  p_user_id uuid,
  p_permission_key text,
  p_tenant_id uuid default null,
  p_resource_id uuid default null
)
returns table (
  allowed boolean,
  employee_id uuid,
  reason text
)
language plpgsql
security definer
set search_path = workforce, pg_catalog
as $$
declare
  v_employee workforce.employees%rowtype;
  v_permission workforce.permissions%rowtype;
  v_has_role boolean;
  v_has_scope boolean;
begin
  if p_user_id is null or p_permission_key is null then
    return query select false, null::uuid, 'invalid_principal_or_permission';
    return;
  end if;

  select e.*
    into v_employee
    from workforce.employees e
   where e.user_id = p_user_id;

  if not found then
    return query select false, null::uuid, 'employee_not_registered';
    return;
  end if;

  if v_employee.status <> 'active' then
    return query select false, v_employee.id, 'employee_not_active';
    return;
  end if;

  select p.*
    into v_permission
    from workforce.permissions p
   where p.permission_key = p_permission_key
     and p.active = true;

  if not found then
    return query select false, v_employee.id, 'permission_not_defined';
    return;
  end if;

  select exists (
    select 1
      from workforce.employee_roles er
      join workforce.roles r on r.id = er.role_id
      join workforce.role_permissions rp on rp.role_id = r.id
     where er.employee_id = v_employee.id
       and er.status = 'active'
       and r.active = true
       and er.valid_from <= now()
       and (er.valid_until is null or er.valid_until > now())
       and rp.permission_id = v_permission.id
  ) into v_has_role;

  if not v_has_role then
    return query select false, v_employee.id, 'role_does_not_grant_permission';
    return;
  end if;

  if not v_permission.scope_required then
    return query select true, v_employee.id, 'allowed';
    return;
  end if;

  if p_tenant_id is null then
    return query select false, v_employee.id, 'tenant_scope_required';
    return;
  end if;

  select exists (
    select 1
      from workforce.employee_scopes es
     where es.employee_id = v_employee.id
       and es.status = 'active'
       and es.valid_from <= now()
       and (es.valid_until is null or es.valid_until > now())
       and (
         (es.scope_type = 'global' and es.scope_id is null)
         or (es.scope_type = 'tenant' and es.scope_id = p_tenant_id)
         or (p_resource_id is not null and es.scope_type = 'resource' and es.scope_id = p_resource_id)
       )
  ) into v_has_scope;

  if not v_has_scope then
    return query select false, v_employee.id, 'scope_not_authorized';
    return;
  end if;

  return query select true, v_employee.id, 'allowed';
end;
$$;

-- Private by construction: no Data API exposure and no direct employee access.
alter table workforce.departments enable row level security;
alter table workforce.employees enable row level security;
alter table workforce.roles enable row level security;
alter table workforce.permissions enable row level security;
alter table workforce.role_permissions enable row level security;
alter table workforce.employee_roles enable row level security;
alter table workforce.employee_scopes enable row level security;
alter table workforce.authority_limits enable row level security;
alter table workforce.sessions enable row level security;
alter table workforce.lifecycle_events enable row level security;
alter table workforce.offboarding_jobs enable row level security;
alter table workforce.offboarding_actions enable row level security;

revoke all on schema workforce from public, anon, authenticated;
grant usage on schema workforce to service_role;

revoke all on all tables in schema workforce from public, anon, authenticated;
grant all on all tables in schema workforce to service_role;

revoke all on all sequences in schema workforce from public, anon, authenticated;
grant all on all sequences in schema workforce to service_role;

revoke all on all routines in schema workforce from public, anon, authenticated;
grant execute on function workforce.authorize(uuid,text,uuid,uuid) to service_role;
grant execute on function workforce.queue_offboarding() to service_role;
grant execute on function workforce.touch_updated_at() to service_role;

alter default privileges for role postgres in schema workforce
  revoke all on tables from public, anon, authenticated;

alter default privileges for role postgres in schema workforce
  revoke all on sequences from public, anon, authenticated;

alter default privileges for role postgres in schema workforce
  revoke execute on routines from public, anon, authenticated;
