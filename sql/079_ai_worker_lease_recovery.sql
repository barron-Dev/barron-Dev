-- 079_ai_worker_lease_recovery.sql
-- Durable worker ownership and crash recovery. A claimed node/run has an
-- explicit lease; expired ownership is reconciled through the canonical
-- transition authority rather than direct state mutation.

alter table public.ai_node_runs
  add column if not exists worker_id text,
  add column if not exists lease_expires_at timestamptz;

create index if not exists idx_ai_node_runs_lease
  on public.ai_node_runs(state,lease_expires_at)
  where state='RUNNING';

create table if not exists public.ai_recovery_attempts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  node_run_id uuid references public.ai_node_runs(id) on delete cascade,
  attempt_no integer not null check (attempt_no > 0),
  reason text not null,
  worker_id text,
  outcome text check (outcome is null or outcome in ('QUEUED','RECOVERED','FAILED','ABANDONED')),
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  unique(run_id,node_run_id,attempt_no)
);

create index if not exists idx_ai_recovery_attempts_run
  on public.ai_recovery_attempts(tenant_id,run_id,created_at desc);

create table if not exists public.ai_reconciliation_queue (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  run_id uuid not null references public.ai_runs(id) on delete cascade,
  node_run_id uuid references public.ai_node_runs(id) on delete cascade,
  reason text not null,
  available_at timestamptz not null default now(),
  claimed_at timestamptz,
  claimed_by text,
  completed_at timestamptz,
  attempts integer not null default 0 check (attempts >= 0),
  last_error text,
  created_at timestamptz not null default now(),
  unique(run_id,node_run_id,reason)
);

create index if not exists idx_ai_reconciliation_ready
  on public.ai_reconciliation_queue(available_at,created_at)
  where completed_at is null;

-- A run is stuck only when it is actively executing and its heartbeat has
-- exceeded the explicit recovery timeout. The timeout is bounded to avoid
-- accidental instant recovery of healthy work.
create or replace function public.ai_find_stuck_runs(
  p_timeout_seconds integer default 180
) returns table(run_id uuid,tenant_id uuid,heartbeat_at timestamptz)
language plpgsql
security definer
set search_path = public,pg_temp
as $$
begin
  if p_timeout_seconds not between 30 and 86400 then
    raise exception 'invalid_stuck_timeout';
  end if;

  return query
  select r.id,r.tenant_id,r.heartbeat_at
    from public.ai_runs r
   where r.run_state in ('RUNNING','STREAMING')
     and coalesce(r.heartbeat_at,r.started_at,r.created_at)
         < now() - make_interval(secs=>p_timeout_seconds)
   order by coalesce(r.heartbeat_at,r.started_at,r.created_at)
   for update skip locked;
end;
$$;

-- Marking STUCK is centralized through ai_transition_run. The reconciliation
-- queue is inserted in the same transaction so detection cannot lose work.
create or replace function public.ai_mark_stuck(
  p_run_id uuid,
  p_reason text default 'heartbeat_timeout',
  p_actor text default 'recovery'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  r public.ai_runs;
  m public.ai_mission_runs;
  q uuid;
begin
  select * into r from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  if r.run_state not in ('RUNNING','STREAMING') then
    return jsonb_build_object('marked',false,'state',r.run_state);
  end if;

  r := public.ai_transition_run(
    p_run_id,'STUCK',left(coalesce(p_reason,'heartbeat_timeout'),1000),p_actor
  );

  insert into public.ai_reconciliation_queue(
    tenant_id,run_id,reason
  ) values (
    r.tenant_id,r.id,left(coalesce(p_reason,'heartbeat_timeout'),1000)
  )
  on conflict (run_id,node_run_id,reason) do nothing
  returning id into q;

  select * into m
    from public.ai_mission_runs
   where run_id=r.id
   for update;

  if found and m.state in ('RUNNING','WAITING_APPROVAL') then
    perform public.ai_transition_mission_run(
      m.id,'STUCK',left(coalesce(p_reason,'heartbeat_timeout'),1000),p_actor
    );
  end if;

  return jsonb_build_object(
    'marked',true,
    'run_id',r.id,
    'state',r.run_state,
    'reconciliation_id',q
  );
end;
$$;

-- Replace node claim with durable ownership. Expired leases are reclaimed
-- only after the prior owner is no longer considered valid.
drop function if exists public.ai_claim_node_run(text,uuid);

create or replace function public.ai_claim_node_run(
  p_worker_id text,
  p_tenant_id uuid,
  p_lease_seconds integer default 120
) returns public.ai_node_runs
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  nr public.ai_node_runs;
begin
  if p_worker_id is null or length(trim(p_worker_id))=0 or length(p_worker_id)>128
     or p_tenant_id is null
     or p_lease_seconds not between 30 and 1800 then
    raise exception 'invalid_worker_lease';
  end if;

  -- Reclaim only expired RUNNING node ownership. The node itself is returned
  -- to QUEUED through the central transition function before a new claim.
  for nr in
    select n.*
      from public.ai_node_runs n
      join public.ai_mission_runs mr on mr.id=n.mission_run_id
      join public.ai_runs r on r.id=mr.run_id
     where n.tenant_id=p_tenant_id
       and n.state='RUNNING'
       and n.lease_expires_at is not null
       and n.lease_expires_at <= now()
       and r.run_state in ('RUNNING','RECOVERING')
       and mr.state in ('RUNNING','WAITING_APPROVAL')
     order by n.lease_expires_at,n.id
     for update of n skip locked
     limit 1
  loop
    perform public.ai_transition_node_run(
      nr.id,'QUEUED','worker_lease_expired',p_worker_id
    );
    update public.ai_node_runs
       set worker_id=null,lease_expires_at=null
     where id=nr.id;
  end loop;

  select n.* into nr
    from public.ai_node_runs n
    join public.ai_mission_runs mr on mr.id=n.mission_run_id
    join public.ai_runs r on r.id=mr.run_id
   where n.tenant_id=p_tenant_id
     and n.state='QUEUED'
     and (n.next_retry_at is null or n.next_retry_at <= now())
     and r.run_state in ('QUEUED','RUNNING','RECOVERING')
     and mr.state in ('QUEUED','RUNNING')
   order by n.next_retry_at nulls first,n.attempt,n.created_at,n.id
   for update of n skip locked
   limit 1;

  if not found then
    return null;
  end if;

  perform public.ai_transition_node_run(
    nr.id,'RUNNING','worker_claim',p_worker_id
  );

  update public.ai_node_runs
     set worker_id=p_worker_id,
         lease_expires_at=now()+make_interval(secs=>p_lease_seconds)
   where id=nr.id
   returning * into nr;

  return nr;
end;
$$;

create or replace function public.ai_heartbeat_node_run(
  p_node_run_id uuid,
  p_worker_id text,
  p_lease_seconds integer default 120
) returns boolean
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare changed integer;
begin
  if p_worker_id is null or length(trim(p_worker_id))=0
     or p_lease_seconds not between 30 and 1800 then
    raise exception 'invalid_worker_lease';
  end if;

  update public.ai_node_runs
     set lease_expires_at=now()+make_interval(secs=>p_lease_seconds)
   where id=p_node_run_id
     and state='RUNNING'
     and worker_id=p_worker_id
     and lease_expires_at > now();

  get diagnostics changed = row_count;
  return changed=1;
end;
$$;

create or replace function public.ai_claim_reconciliation(
  p_worker_id text,
  p_limit integer default 10
) returns setof public.ai_reconciliation_queue
language plpgsql
security definer
set search_path = public,pg_temp
as $$
begin
  if p_worker_id is null or length(trim(p_worker_id))=0
     or p_limit not between 1 and 100 then
    raise exception 'invalid_reconciliation_worker';
  end if;

  return query
  with picked as (
    select q.id
      from public.ai_reconciliation_queue q
     where q.completed_at is null
       and q.available_at <= now()
       and (q.claimed_at is null or q.claimed_at < now()-interval '10 minutes')
     order by q.available_at,q.created_at,q.id
     for update skip locked
     limit p_limit
  )
  update public.ai_reconciliation_queue q
     set claimed_at=now(),
         claimed_by=left(p_worker_id,128),
         attempts=attempts+1
    from picked
   where q.id=picked.id
  returning q.*;
end;
$$;

create or replace function public.ai_complete_reconciliation(
  p_queue_id uuid,
  p_worker_id text,
  p_success boolean,
  p_error text default null
) returns boolean
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare changed integer;
begin
  update public.ai_reconciliation_queue
     set completed_at=case when p_success then now() else null end,
         claimed_at=case when p_success then claimed_at else null end,
         claimed_by=case when p_success then claimed_by else null end,
         last_error=case when p_success then null else left(coalesce(p_error,'reconciliation failed'),2000) end,
         available_at=case when p_success then available_at else now()+interval '30 seconds' end
   where id=p_queue_id
     and claimed_by=p_worker_id
     and claimed_at is not null
     and completed_at is null;

  get diagnostics changed=row_count;
  return changed=1;
end;
$$;

-- Release node leases on terminal completion so concurrency ownership cannot
-- survive successful execution.
create or replace function public.ai_record_node_completion(
  p_node_run_id uuid,
  p_success boolean,
  p_output_hash text default null,
  p_worker_id text default null
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  nr public.ai_node_runs;
  mr public.ai_mission_runs;
  r public.ai_runs;
  v_total integer;
  v_done integer;
  v_terminal text;
begin
  select * into nr from public.ai_node_runs where id=p_node_run_id for update;
  if not found then raise exception 'node_run_not_found'; end if;

  if nr.state <> 'RUNNING' then
    return jsonb_build_object('completed',false,'state',nr.state);
  end if;

  if p_worker_id is not null and nr.worker_id <> p_worker_id then
    raise exception 'worker_lease_mismatch';
  end if;

  if nr.lease_expires_at is not null and nr.lease_expires_at <= now() then
    raise exception 'worker_lease_expired';
  end if;

  v_terminal := case when p_success then 'COMPLETED' else 'FAILED' end;

  perform public.ai_transition_node_run(
    nr.id,v_terminal,case when p_success then null else 'node_execution_failed' end,
    coalesce(p_worker_id,'worker')
  );

  update public.ai_node_runs
     set output_hash=p_output_hash,
         worker_id=null,
         lease_expires_at=null
   where id=nr.id
   returning * into nr;

  select * into mr from public.ai_mission_runs
   where id=nr.mission_run_id for update;

  select count(*) into v_total
    from public.ai_node_runs
   where mission_run_id=mr.id and attempt=1;

  select count(*) into v_done
    from public.ai_node_runs
   where mission_run_id=mr.id
     and attempt=1
     and state in ('COMPLETED','SKIPPED');

  update public.ai_mission_runs
     set completed_nodes=v_done,
         node_count=v_total
   where id=mr.id;

  if v_total > 0 and v_done=v_total then
    perform public.ai_transition_mission_run(
      mr.id,'COMPLETED','all_nodes_completed',coalesce(p_worker_id,'worker')
    );

    select * into r from public.ai_runs where id=mr.run_id for update;

    if r.run_state in ('RUNNING','STREAMING','RECOVERING') then
      perform public.ai_transition_run(
        r.id,'COMPLETED','mission_completed',coalesce(p_worker_id,'worker')
      );
    end if;
  elsif not p_success then
    perform public.ai_transition_mission_run(
      mr.id,'FAILED','node_failed',coalesce(p_worker_id,'worker')
    );
  end if;

  return jsonb_build_object(
    'completed',true,
    'node_run_id',nr.id,
    'node_state',nr.state,
    'mission_run_id',mr.id
  );
end;
$$;

-- Keep privileged worker/recovery surfaces out of browser/API roles.
alter table public.ai_recovery_attempts enable row level security;
alter table public.ai_reconciliation_queue enable row level security;

revoke all on table public.ai_recovery_attempts,public.ai_reconciliation_queue
  from anon,authenticated;

revoke all on function public.ai_find_stuck_runs(integer)
  from public,anon,authenticated;
revoke all on function public.ai_mark_stuck(uuid,text,text)
  from public,anon,authenticated;
revoke all on function public.ai_claim_node_run(text,uuid,integer)
  from public,anon,authenticated;
revoke all on function public.ai_heartbeat_node_run(uuid,text,integer)
  from public,anon,authenticated;
revoke all on function public.ai_claim_reconciliation(text,integer)
  from public,anon,authenticated;
revoke all on function public.ai_complete_reconciliation(uuid,text,boolean,text)
  from public,anon,authenticated;
revoke all on function public.ai_record_node_completion(uuid,boolean,text,text)
  from public,anon,authenticated;

grant execute on function public.ai_find_stuck_runs(integer) to service_role;
grant execute on function public.ai_mark_stuck(uuid,text,text) to service_role;
grant execute on function public.ai_claim_node_run(text,uuid,integer) to service_role;
grant execute on function public.ai_heartbeat_node_run(uuid,text,integer) to service_role;
grant execute on function public.ai_claim_reconciliation(text,integer) to service_role;
grant execute on function public.ai_complete_reconciliation(uuid,text,boolean,text) to service_role;
grant execute on function public.ai_record_node_completion(uuid,boolean,text,text) to service_role;

comment on table public.ai_reconciliation_queue is
'Durable recovery work queue. Detection and queue insertion occur transactionally; workers claim with SKIP LOCKED.';
