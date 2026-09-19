-- 080_ai_worker_lease_transition_hardening.sql
-- Hardens 079 without creating a second executor.
-- Fixes expired-lease state recovery, closes the legacy completion overload,
-- ties worker heartbeats to the parent run, and makes recovery accounting
-- durable and bounded.

-- 1. Expired RUNNING nodes cannot jump directly to QUEUED because the canonical
-- node state machine intentionally requires a terminal recovery state first.
-- Reclaim through TIMEOUT -> QUEUED, preserving the existing transition graph
-- and making the recovery reason durable in the node error field.

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
  recovery_run uuid;
  recovery_tenant uuid;
  recovery_attempt_no integer;
begin
  if p_worker_id is null or length(trim(p_worker_id))=0 or length(p_worker_id)>128
     or p_tenant_id is null
     or p_lease_seconds not between 30 and 1800 then
    raise exception 'invalid_worker_lease';
  end if;

  -- Reclaim one expired node at a time. The old owner has lost authority;
  -- transition through TIMEOUT before requeueing so no illegal state edge exists.
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
    recovery_run := nr.run_id;
    recovery_tenant := nr.tenant_id;

    select count(*) + 1
      into recovery_attempt_no
      from public.ai_recovery_attempts
     where run_id=recovery_run
       and node_run_id=nr.id;

    perform public.ai_transition_node_run(
      nr.id,'TIMEOUT','worker_lease_expired',p_worker_id
    );

    update public.ai_node_runs
       set worker_id=null,
           lease_expires_at=null,
           next_retry_at=now()
     where id=nr.id;

    insert into public.ai_recovery_attempts(
      tenant_id,run_id,node_run_id,attempt_no,reason,worker_id,outcome
    ) values (
      recovery_tenant,recovery_run,nr.id,recovery_attempt_no,
      'worker_lease_expired',left(p_worker_id,128),'QUEUED'
    )
    on conflict (run_id,node_run_id,attempt_no) do nothing;

    perform public.ai_transition_node_run(
      nr.id,'QUEUED','worker_lease_requeued',p_worker_id
    );
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

  update public.ai_runs
     set heartbeat_at=now()
   where id=nr.run_id
     and run_state in ('QUEUED','RUNNING','RECOVERING');

  return nr;
end;
$$;

-- 2. A healthy node worker is also proof of liveness for its parent run.
-- Prevent the run-level recovery detector from declaring a live run STUCK.

create or replace function public.ai_heartbeat_node_run(
  p_node_run_id uuid,
  p_worker_id text,
  p_lease_seconds integer default 120
) returns boolean
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  changed integer;
  v_run_id uuid;
begin
  if p_worker_id is null or length(trim(p_worker_id))=0
     or p_lease_seconds not between 30 and 1800 then
    raise exception 'invalid_worker_lease';
  end if;

  update public.ai_node_runs n
     set lease_expires_at=now()+make_interval(secs=>p_lease_seconds)
    from public.ai_mission_runs mr
    join public.ai_runs r on r.id=mr.run_id
   where n.id=p_node_run_id
     and mr.id=n.mission_run_id
     and n.state='RUNNING'
     and n.worker_id=p_worker_id
     and n.lease_expires_at > now()
  returning r.id into v_run_id;

  get diagnostics changed = row_count;

  if changed=1 then
    update public.ai_runs
       set heartbeat_at=now()
     where id=v_run_id
       and run_state in ('RUNNING','STREAMING','RECOVERING');
  end if;

  return changed=1;
end;
$$;

-- 3. Every reconciliation claim gets a durable recovery-attempt record.
-- This makes repeated crashes observable and auditable.

create or replace function public.ai_claim_reconciliation(
  p_worker_id text,
  p_limit integer default 10
) returns setof public.ai_reconciliation_queue
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  q public.ai_reconciliation_queue;
  v_attempt_no integer;
begin
  if p_worker_id is null or length(trim(p_worker_id))=0
     or p_limit not between 1 and 100 then
    raise exception 'invalid_reconciliation_worker';
  end if;

  for q in
    with picked as (
      select x.id
        from public.ai_reconciliation_queue x
       where x.completed_at is null
         and x.available_at <= now()
         and (x.claimed_at is null or x.claimed_at < now()-interval '10 minutes')
       order by x.available_at,x.created_at,x.id
       for update skip locked
       limit p_limit
    )
    update public.ai_reconciliation_queue x
       set claimed_at=now(),
           claimed_by=left(p_worker_id,128),
           attempts=attempts+1
      from picked
     where x.id=picked.id
     returning x.*
  loop
    select count(*) + 1
      into v_attempt_no
      from public.ai_recovery_attempts
     where run_id=q.run_id
       and (node_run_id is not distinct from q.node_run_id);

    insert into public.ai_recovery_attempts(
      tenant_id,run_id,node_run_id,attempt_no,reason,worker_id,outcome
    ) values (
      q.tenant_id,q.run_id,q.node_run_id,v_attempt_no,
      left(q.reason,1000),left(p_worker_id,128),'QUEUED'
    )
    on conflict (run_id,node_run_id,attempt_no) do nothing;

    return next q;
  end loop;

  return;
end;
$$;

-- 4. Make run-level/node-level queue uniqueness correct with PostgreSQL NULL
-- semantics. Existing constraints remain as compatibility constraints.

create unique index if not exists uq_ai_reconciliation_run_reason
  on public.ai_reconciliation_queue(run_id,reason)
  where node_run_id is null;

create unique index if not exists uq_ai_reconciliation_node_reason
  on public.ai_reconciliation_queue(run_id,node_run_id,reason)
  where node_run_id is not null;

create unique index if not exists uq_ai_recovery_attempt_run
  on public.ai_recovery_attempts(run_id,attempt_no)
  where node_run_id is null;

create unique index if not exists uq_ai_recovery_attempt_node
  on public.ai_recovery_attempts(run_id,node_run_id,attempt_no)
  where node_run_id is not null;

-- 5. Bound reconciliation retries. After five failed claims, the item is
-- abandoned rather than becoming an infinite hot loop. The durable attempt
-- row records the terminal outcome.

alter table public.ai_reconciliation_queue
  add column if not exists abandoned_at timestamptz;

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
declare
  q public.ai_reconciliation_queue;
  changed integer;
  v_attempt_no integer;
  v_abandon boolean;
begin
  select * into q
    from public.ai_reconciliation_queue
   where id=p_queue_id
   for update;

  if not found
     or q.claimed_by <> p_worker_id
     or q.claimed_at is null
     or q.completed_at is not null then
    return false;
  end if;

  v_abandon := (not p_success and q.attempts >= 5);

  update public.ai_reconciliation_queue
     set completed_at=case when p_success then now() else null end,
         abandoned_at=case when v_abandon then now() else abandoned_at end,
         claimed_at=case when p_success or v_abandon then claimed_at else null end,
         claimed_by=case when p_success or v_abandon then claimed_by else null end,
         last_error=case when p_success then null else left(coalesce(p_error,'reconciliation failed'),2000) end,
         available_at=case
           when p_success then available_at
           when v_abandon then available_at
           else now()+least(interval '5 minutes',make_interval(secs=>greatest(30,q.attempts*30)))
         end
   where id=q.id;

  get diagnostics changed=row_count;

  if changed=1 then
    select count(*) + 1
      into v_attempt_no
      from public.ai_recovery_attempts
     where run_id=q.run_id
       and (node_run_id is not distinct from q.node_run_id);

    update public.ai_recovery_attempts
       set outcome=case
                    when p_success then 'RECOVERED'
                    when v_abandon then 'ABANDONED'
                    else 'FAILED'
                  end,
           completed_at=now()
     where run_id=q.run_id
       and (node_run_id is not distinct from q.node_run_id)
       and attempt_no=greatest(1,q.attempts);

    return true;
  end if;

  return false;
end;
$$;

-- 6. Close the legacy 3-argument completion path from 076. There must be one
-- completion authority, and production workers must use the lease-aware API.

drop function if exists public.ai_record_node_completion(uuid,boolean,text);

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

grant execute on function public.ai_claim_node_run(text,uuid,integer) to service_role;
grant execute on function public.ai_heartbeat_node_run(uuid,text,integer) to service_role;
grant execute on function public.ai_claim_reconciliation(text,integer) to service_role;
grant execute on function public.ai_complete_reconciliation(uuid,text,boolean,text) to service_role;
grant execute on function public.ai_record_node_completion(uuid,boolean,text,text) to service_role;

comment on function public.ai_claim_node_run is
'Single worker claim boundary. Expired ownership is recovered through TIMEOUT -> QUEUED, never by bypassing the canonical state graph.';

comment on column public.ai_reconciliation_queue.abandoned_at is
'Terminal timestamp after bounded reconciliation attempts are exhausted; requires operator/recovery policy review.';
