-- 082_workforce_ai_mission_boundary.sql
-- Controlled internal AI boundary.
-- GitHub-only: do not apply to production without explicit authorization.
-- Internal AI is a work assistant, not a general-purpose personal assistant.
-- Every employee AI session is bound to an approved mission and workforce scope.

create type workforce.ai_session_status as enum (
  'active',
  'revoked',
  'expired',
  'completed'
);

create table workforce.ai_mission_assignments (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references workforce.employees(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  mission_id uuid not null references public.ai_missions(id) on delete cascade,
  mission_version integer not null check (mission_version > 0),
  mission_hash text not null check (mission_hash ~ '^[0-9a-f]{64}$'),
  status workforce.assignment_status not null default 'active',
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  assigned_by uuid references workforce.employees(id) on delete restrict,
  created_at timestamptz not null default now(),
  check (valid_until is null or valid_until > valid_from),
  unique (employee_id, tenant_id, mission_id, mission_version)
);

create index workforce_ai_mission_assignment_lookup
  on workforce.ai_mission_assignments(employee_id, tenant_id, status, valid_from, valid_until);

create table workforce.ai_sessions (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references workforce.employees(id) on delete cascade,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  mission_assignment_id uuid not null references workforce.ai_mission_assignments(id) on delete restrict,
  status workforce.ai_session_status not null default 'active',
  started_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  completed_at timestamptz,
  last_turn_at timestamptz,
  check (expires_at > started_at),
  check (revoked_at is null or revoked_at >= started_at)
);

create index workforce_ai_sessions_employee_idx
  on workforce.ai_sessions(employee_id, status, expires_at);

create table workforce.ai_turns (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references workforce.ai_sessions(id) on delete cascade,
  employee_id uuid not null references workforce.employees(id) on delete restrict,
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  mission_id uuid not null references public.ai_missions(id) on delete restrict,
  mission_version integer not null check (mission_version > 0),
  mission_hash text not null check (mission_hash ~ '^[0-9a-f]{64}$'),
  sequence_no bigint not null check (sequence_no > 0),
  input_hash text not null check (input_hash ~ '^[0-9a-f]{64}$'),
  output_hash text,
  requested_action text,
  status text not null default 'accepted'
    check (status in ('accepted','completed','rejected','failed')),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (session_id, sequence_no)
);

create index workforce_ai_turns_tenant_created_idx
  on workforce.ai_turns(tenant_id, created_at desc);

create or replace function workforce.authorize_ai_session(
  p_user_id uuid,
  p_tenant_id uuid,
  p_mission_id uuid,
  p_mission_version integer,
  p_mission_hash text
)
returns table (
  allowed boolean,
  employee_id uuid,
  mission_assignment_id uuid,
  session_id uuid,
  reason text
)
language plpgsql
security definer
set search_path = workforce, pg_catalog
as $$
declare
  v_employee workforce.employees%rowtype;
  v_assignment workforce.ai_mission_assignments%rowtype;
  v_session workforce.ai_sessions%rowtype;
begin
  if p_user_id is null
     or p_tenant_id is null
     or p_mission_id is null
     or p_mission_version is null
     or p_mission_hash is null then
    return query select false, null::uuid, null::uuid, null::uuid,
      'invalid_ai_session_request';
    return;
  end if;

  select e.*
    into v_employee
    from workforce.employees e
   where e.user_id = p_user_id;

  if not found or v_employee.status <> 'active' then
    return query select false, coalesce(v_employee.id, null::uuid),
      null::uuid, null::uuid, 'employee_not_active';
    return;
  end if;

  select a.*
    into v_assignment
    from workforce.ai_mission_assignments a
   where a.employee_id = v_employee.id
     and a.tenant_id = p_tenant_id
     and a.mission_id = p_mission_id
     and a.mission_version = p_mission_version
     and a.mission_hash = p_mission_hash
     and a.status = 'active'
     and a.valid_from <= now()
     and (a.valid_until is null or a.valid_until > now())
   order by a.created_at desc
   limit 1;

  if not found then
    return query select false, v_employee.id, null::uuid, null::uuid,
      'ai_mission_not_authorized';
    return;
  end if;

  -- A terminated/suspended employee cannot retain an active AI session.
  update workforce.ai_sessions
     set status = 'revoked',
         revoked_at = coalesce(revoked_at, now())
   where employee_id = v_employee.id
     and status = 'active'
     and expires_at <= now();

  insert into workforce.ai_sessions (
    employee_id,
    tenant_id,
    mission_assignment_id,
    expires_at
  )
  values (
    v_employee.id,
    p_tenant_id,
    v_assignment.id,
    now() + interval '30 minutes'
  )
  returning * into v_session;

  return query select true, v_employee.id, v_assignment.id, v_session.id,
    'allowed';
end;
$$;

create or replace function workforce.revoke_employee_ai(
  p_employee_id uuid,
  p_reason text
)
returns integer
language plpgsql
security definer
set search_path = workforce, pg_catalog
as $$
declare
  v_count integer;
begin
  update workforce.ai_sessions
     set status = 'revoked',
         revoked_at = coalesce(revoked_at, now())
   where employee_id = p_employee_id
     and status = 'active';

  get diagnostics v_count = row_count;

  update workforce.ai_mission_assignments
     set status = 'revoked',
         valid_until = least(coalesce(valid_until, now()), now())
   where employee_id = p_employee_id
     and status = 'active';

  insert into workforce.lifecycle_events (
    employee_id,
    event_type,
    reason,
    metadata
  )
  values (
    p_employee_id,
    'offboarding_started',
    coalesce(p_reason, 'employee_ai_revocation'),
    jsonb_build_object('ai_sessions_revoked', v_count)
  );

  return v_count;
end;
$$;

-- Extend the existing employee termination kill-chain with immediate AI revocation.
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

    update workforce.employee_scopes
       set status = 'revoked',
           valid_until = least(coalesce(valid_until, now()), now())
     where employee_id = new.id
       and status = 'active';

    perform workforce.revoke_employee_ai(new.id, 'employee_terminated');

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

alter table workforce.ai_mission_assignments enable row level security;
alter table workforce.ai_sessions enable row level security;
alter table workforce.ai_turns enable row level security;

revoke all on workforce.ai_mission_assignments, workforce.ai_sessions, workforce.ai_turns
  from public, anon, authenticated;

grant all on workforce.ai_mission_assignments, workforce.ai_sessions, workforce.ai_turns
  to service_role;

revoke all on all routines in schema workforce from public, anon, authenticated;

grant execute on function workforce.authorize_ai_session(uuid,uuid,uuid,integer,text)
  to service_role;

grant execute on function workforce.revoke_employee_ai(uuid,text)
  to service_role;

grant execute on function workforce.queue_offboarding()
  to service_role;
