-- 072_ai_execution_admission_kernel.sql
-- Cyclothone foundation block 2:
-- atomic budget reservation + token-bucket rate admission + concurrency leases.
-- No browser mutation path. This is an execution-control primitive, not a UI API.

create table if not exists public.ai_budgets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  scope text not null check (scope in ('TENANT','AGENT','MISSION','MODEL','PROVIDER','TOOL')),
  scope_id text,
  period text not null check (period in ('DAY','MONTH')),
  period_start timestamptz not null,
  limit_usd numeric(18,8) not null check (limit_usd >= 0),
  reserved_usd numeric(18,8) not null default 0 check (reserved_usd >= 0),
  consumed_usd numeric(18,8) not null default 0 check (consumed_usd >= 0),
  hard_stop boolean not null default true,
  updated_at timestamptz not null default now(),
  unique (tenant_id,scope,scope_id,period,period_start)
);

create index if not exists idx_ai_budgets_lookup
  on public.ai_budgets(tenant_id,scope,scope_id,period,period_start);

create table if not exists public.ai_budget_reservations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  budget_id uuid not null references public.ai_budgets(id) on delete cascade,
  amount_usd numeric(18,8) not null check (amount_usd > 0),
  state text not null default 'RESERVED'
    check (state in ('RESERVED','SETTLED','RELEASED')),
  created_at timestamptz not null default now(),
  settled_at timestamptz,
  unique (run_id,budget_id)
);

create index if not exists idx_ai_budget_reservations_run
  on public.ai_budget_reservations(run_id,state);

create table if not exists public.ai_rate_limits (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  scope text not null check (scope in ('TENANT','AGENT','MISSION','MODEL','PROVIDER','TOOL')),
  scope_id text,
  max_concurrent integer check (max_concurrent is null or max_concurrent > 0),
  rate_per_sec numeric(18,6) check (rate_per_sec is null or rate_per_sec > 0),
  burst numeric(18,6) check (burst is null or burst > 0),
  queue_depth integer check (queue_depth is null or queue_depth >= 0),
  tokens numeric(18,6) not null default 0,
  token_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id,scope,scope_id)
);

create table if not exists public.ai_admission_leases (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  scope text not null check (scope in ('TENANT','AGENT','MISSION','MODEL','PROVIDER','TOOL')),
  scope_id text not null,
  granted_at timestamptz not null default now(),
  expires_at timestamptz not null,
  released_at timestamptz,
  unique (run_id,scope,scope_id)
);

create index if not exists idx_ai_admission_active
  on public.ai_admission_leases(tenant_id,scope,scope_id,expires_at)
  where released_at is null;

-- Exact period boundaries. UTC is deliberate: billing windows must not depend
-- on worker/server timezone.
create or replace function public.ai_budget_period_start(
  p_period text, p_at timestamptz default now()
) returns timestamptz
language sql immutable
as $$
  select case p_period
    when 'DAY' then date_trunc('day',p_at at time zone 'UTC') at time zone 'UTC'
    when 'MONTH' then date_trunc('month',p_at at time zone 'UTC') at time zone 'UTC'
  end
$$;

-- Refresh a token bucket while holding its row lock.
create or replace function public.ai_rate_refresh_locked(
  p_rate_id uuid, p_now timestamptz
) returns public.ai_rate_limits
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_rate_limits; elapsed numeric;
begin
  select * into r from public.ai_rate_limits where id=p_rate_id for update;
  if not found then raise exception 'rate_limit_not_found'; end if;

  if r.rate_per_sec is null or r.burst is null then
    return r;
  end if;

  elapsed := greatest(extract(epoch from (p_now-r.token_at)),0);
  r.tokens := least(r.burst, r.tokens + elapsed*r.rate_per_sec);

  update public.ai_rate_limits
     set tokens=r.tokens, token_at=p_now, updated_at=p_now
   where id=r.id
   returning * into r;
  return r;
end;
$$;

-- Admission is one transaction: all budget rows and all rate/concurrency rows
-- are locked before any reservation is created. The ordered lock prevents
-- cross-request deadlocks when multiple scopes are involved.
create or replace function public.ai_admit_execution(
  p_tenant_id uuid,
  p_run_id uuid,
  p_agent_id uuid,
  p_mission_id text,
  p_model_id text,
  p_provider_id text,
  p_tool_id text,
  p_estimated_cost_usd numeric(18,8),
  p_lease_seconds integer default 600
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  v_now timestamptz := now();
  v_period text;
  v_period_start timestamptz;
  v_budget public.ai_budgets;
  v_rate public.ai_rate_limits;
  v_scope record;
  v_active integer;
  v_reserved numeric;
  v_reason text;
  v_lease_until timestamptz;
begin
  if p_tenant_id is null or p_run_id is null or p_estimated_cost_usd is null
     or p_estimated_cost_usd < 0
     or p_lease_seconds not between 30 and 3600 then
    raise exception 'invalid_admission_request';
  end if;

  if not exists (
    select 1 from public.ai_runs
     where id=p_run_id and tenant_id=p_tenant_id
  ) then
    raise exception 'run_not_found';
  end if;

  -- Idempotent retry: an already admitted run returns its current admission.
  if exists (
    select 1 from public.ai_budget_reservations
     where run_id=p_run_id and state='RESERVED'
  ) or exists (
    select 1 from public.ai_admission_leases
     where run_id=p_run_id and released_at is null and expires_at > v_now
  ) then
    return jsonb_build_object('ok',true,'already_admitted',true);
  end if;

  -- Serialize against every scope in deterministic lexical order.
  for v_scope in
    select scope,scope_id
      from (values
        ('AGENT',p_agent_id::text),
        ('MISSION',p_mission_id),
        ('MODEL',p_model_id),
        ('PROVIDER',p_provider_id),
        ('TENANT',p_tenant_id::text),
        ('TOOL',p_tool_id)
      ) x(scope,scope_id)
     where scope_id is not null
     order by scope,scope_id
  loop
    select * into v_rate
      from public.ai_rate_limits
     where tenant_id=p_tenant_id
       and scope=v_scope.scope
       and scope_id=v_scope.scope_id
     for update;

    if found then
      v_rate := public.ai_rate_refresh_locked(v_rate.id,v_now);

      if v_rate.max_concurrent is not null then
        delete from public.ai_admission_leases
         where tenant_id=p_tenant_id
           and scope=v_scope.scope
           and scope_id=v_scope.scope_id
           and released_at is null
           and expires_at <= v_now;

        select count(*) into v_active
          from public.ai_admission_leases
         where tenant_id=p_tenant_id
           and scope=v_scope.scope
           and scope_id=v_scope.scope_id
           and released_at is null;

        if v_active >= v_rate.max_concurrent then
          return jsonb_build_object('ok',false,'reason','concurrency_limit',
                                    'scope',v_scope.scope);
        end if;
      end if;

      if v_rate.rate_per_sec is not null and v_rate.burst is not null then
        if v_rate.tokens < 1 then
          return jsonb_build_object('ok',false,'reason','rate_limit',
                                    'scope',v_scope.scope);
        end if;
      end if;
    end if;
  end loop;

  -- Atomic budget check/reservation for every configured budget scope.
  if p_estimated_cost_usd > 0 then
    for v_period in select unnest(array['DAY','MONTH'])
    loop
      v_period_start := public.ai_budget_period_start(v_period,v_now);

      for v_budget in
        select * from public.ai_budgets
         where tenant_id=p_tenant_id
           and period=v_period
           and period_start=v_period_start
           and (
             (scope='TENANT' and scope_id=p_tenant_id::text) or
             (scope='AGENT' and scope_id=p_agent_id::text) or
             (scope='MISSION' and scope_id=p_mission_id) or
             (scope='MODEL' and scope_id=p_model_id) or
             (scope='PROVIDER' and scope_id=p_provider_id) or
             (scope='TOOL' and scope_id=p_tool_id)
           )
         order by scope,scope_id
         for update
      loop
        if v_budget.hard_stop
           and v_budget.consumed_usd + v_budget.reserved_usd + p_estimated_cost_usd
               > v_budget.limit_usd then
          return jsonb_build_object('ok',false,'reason','budget_exceeded',
                                    'scope',v_budget.scope);
        end if;
      end loop;
    end loop;

    for v_period in select unnest(array['DAY','MONTH'])
    loop
      v_period_start := public.ai_budget_period_start(v_period,v_now);

      for v_budget in
        select * from public.ai_budgets
         where tenant_id=p_tenant_id
           and period=v_period
           and period_start=v_period_start
           and (
             (scope='TENANT' and scope_id=p_tenant_id::text) or
             (scope='AGENT' and scope_id=p_agent_id::text) or
             (scope='MISSION' and scope_id=p_mission_id) or
             (scope='MODEL' and scope_id=p_model_id) or
             (scope='PROVIDER' and scope_id=p_provider_id) or
             (scope='TOOL' and scope_id=p_tool_id)
           )
         order by scope,scope_id
      loop
        update public.ai_budgets
           set reserved_usd=reserved_usd+p_estimated_cost_usd,
               updated_at=v_now
         where id=v_budget.id;

        insert into public.ai_budget_reservations
          (tenant_id,run_id,budget_id,amount_usd)
        values
          (p_tenant_id,p_run_id,v_budget.id,p_estimated_cost_usd)
        on conflict (run_id,budget_id) do update
          set state='RESERVED',settled_at=null;
      end loop;
    end loop;
  end if;

  -- Consume exactly one token from each configured rate bucket.
  for v_scope in
    select scope,scope_id
      from (values
        ('AGENT',p_agent_id::text),
        ('MISSION',p_mission_id),
        ('MODEL',p_model_id),
        ('PROVIDER',p_provider_id),
        ('TENANT',p_tenant_id::text),
        ('TOOL',p_tool_id)
      ) x(scope,scope_id)
     where scope_id is not null
     order by scope,scope_id
  loop
    select * into v_rate
      from public.ai_rate_limits
     where tenant_id=p_tenant_id and scope=v_scope.scope and scope_id=v_scope.scope_id
     for update;

    if found and v_rate.rate_per_sec is not null and v_rate.burst is not null then
      update public.ai_rate_limits
         set tokens=greatest(tokens-1,0),updated_at=v_now
       where id=v_rate.id;
    end if;
  end loop;

  v_lease_until := v_now + make_interval(secs=>p_lease_seconds);

  insert into public.ai_admission_leases
    (tenant_id,run_id,scope,scope_id,granted_at,expires_at)
  select p_tenant_id,p_run_id,s.scope,s.scope_id,v_now,v_lease_until
    from (values
      ('AGENT',p_agent_id::text),('MISSION',p_mission_id),
      ('MODEL',p_model_id),('PROVIDER',p_provider_id),
      ('TENANT',p_tenant_id::text),('TOOL',p_tool_id)
    ) s(scope,scope_id)
   where s.scope_id is not null
  on conflict (run_id,scope,scope_id) do update
    set expires_at=excluded.expires_at,released_at=null;

  return jsonb_build_object(
    'ok',true,
    'lease_expires_at',v_lease_until,
    'estimated_cost_usd',p_estimated_cost_usd
  );
end;
$$;

create or replace function public.ai_settle_execution(
  p_run_id uuid,
  p_actual_cost_usd numeric(18,8)
) returns void
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r record;
begin
  if p_actual_cost_usd is null or p_actual_cost_usd < 0 then
    raise exception 'invalid_actual_cost';
  end if;

  for r in
    select br.id,br.budget_id,br.amount_usd,b.tenant_id
      from public.ai_budget_reservations br
      join public.ai_budgets b on b.id=br.budget_id
     where br.run_id=p_run_id and br.state='RESERVED'
     for update of br,b
  loop
    update public.ai_budgets
       set reserved_usd=greatest(reserved_usd-r.amount_usd,0),
           consumed_usd=consumed_usd+p_actual_cost_usd,
           updated_at=now()
     where id=r.budget_id;

    update public.ai_budget_reservations
       set state='SETTLED',settled_at=now()
     where id=r.id;
  end loop;

  update public.ai_admission_leases
     set released_at=now()
   where run_id=p_run_id and released_at is null;
end;
$$;

create or replace function public.ai_release_execution(
  p_run_id uuid
) returns void
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r record;
begin
  for r in
    select br.id,br.budget_id,br.amount_usd
      from public.ai_budget_reservations br
     where br.run_id=p_run_id and br.state='RESERVED'
     for update
  loop
    update public.ai_budgets
       set reserved_usd=greatest(reserved_usd-r.amount_usd,0),
           updated_at=now()
     where id=r.budget_id;

    update public.ai_budget_reservations
       set state='RELEASED',settled_at=now()
     where id=r.id;
  end loop;

  update public.ai_admission_leases
     set released_at=now()
   where run_id=p_run_id and released_at is null;
end;
$$;

alter table public.ai_budgets enable row level security;
alter table public.ai_budget_reservations enable row level security;
alter table public.ai_rate_limits enable row level security;
alter table public.ai_admission_leases enable row level security;

revoke all on table public.ai_budgets,public.ai_budget_reservations,
  public.ai_rate_limits,public.ai_admission_leases from anon,authenticated;

revoke all on function public.ai_admit_execution(uuid,uuid,uuid,text,text,text,text,numeric,integer)
  from public,anon,authenticated;
revoke all on function public.ai_settle_execution(uuid,numeric)
  from public,anon,authenticated;
revoke all on function public.ai_release_execution(uuid)
  from public,anon,authenticated;
revoke all on function public.ai_rate_refresh_locked(uuid,timestamptz)
  from public,anon,authenticated;

grant execute on function public.ai_admit_execution(uuid,uuid,uuid,text,text,text,text,numeric,integer) to service_role;
grant execute on function public.ai_settle_execution(uuid,numeric) to service_role;
grant execute on function public.ai_release_execution(uuid) to service_role;
grant execute on function public.ai_rate_refresh_locked(uuid,timestamptz) to service_role;

comment on function public.ai_admit_execution is
'Canonical atomic execution admission: deterministic row locks, token bucket, concurrency lease, and multi-scope budget reservation.';

comment on table public.ai_budget_reservations is
'Durable financial reservation ledger. RESERVED is held before execution; SETTLED records actual cost; RELEASED returns unused reservation.';

comment on table public.ai_admission_leases is
'Durable concurrency ownership. Expiry is the crash-recovery boundary; released_at is the normal completion boundary.';
