-- 076_ai_mission_execution_authority.sql
-- Centralize mission/node/tool execution state and provide a crash-safe worker
-- claim boundary. No second executor is introduced.

create or replace function public.ai_assert_mission_transition(
  p_from text, p_to text
) returns boolean
language sql immutable strict
as $$
  select case p_from
    when 'QUEUED' then p_to in ('RUNNING','CANCELLED','FAILED','STUCK')
    when 'RUNNING' then p_to in ('WAITING_APPROVAL','COMPLETED','FAILED','CANCELLED','STUCK')
    when 'WAITING_APPROVAL' then p_to in ('RUNNING','COMPLETED','FAILED','CANCELLED','STUCK')
    when 'STUCK' then p_to in ('RUNNING','FAILED','CANCELLED')
    else false
  end
$$;

create or replace function public.ai_assert_node_transition(
  p_from text, p_to text
) returns boolean
language sql immutable strict
as $$
  select case p_from
    when 'QUEUED' then p_to in ('RUNNING','SKIPPED','CANCELLED','TIMEOUT')
    when 'RUNNING' then p_to in ('COMPLETED','FAILED','TIMEOUT','CANCELLED')
    when 'FAILED' then p_to in ('QUEUED','CANCELLED')
    when 'TIMEOUT' then p_to in ('QUEUED','CANCELLED')
    else false
  end
$$;

create or replace function public.ai_assert_tool_transition(
  p_from text, p_to text
) returns boolean
language sql immutable strict
as $$
  select case p_from
    when 'QUEUED' then p_to in ('RUNNING','BLOCKED','APPROVAL_REQUIRED','CANCELLED')
    when 'RUNNING' then p_to in ('COMPLETED','FAILED','TIMEOUT','CANCELLED')
    when 'BLOCKED' then p_to in ('QUEUED','CANCELLED')
    when 'APPROVAL_REQUIRED' then p_to in ('QUEUED','CANCELLED')
    when 'FAILED' then p_to in ('QUEUED','CANCELLED')
    when 'TIMEOUT' then p_to in ('QUEUED','CANCELLED')
    else false
  end
$$;

create or replace function public.ai_transition_mission_run(
  p_mission_run_id uuid,
  p_to text,
  p_reason text default null,
  p_actor text default 'system'
) returns public.ai_mission_runs
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_mission_runs;
begin
  select * into r from public.ai_mission_runs
   where id=p_mission_run_id for update;
  if not found then raise exception 'mission_run_not_found'; end if;
  if not public.ai_assert_mission_transition(r.state,p_to) then
    raise exception 'invalid_mission_transition:%->%',r.state,p_to;
  end if;

  update public.ai_mission_runs
     set state=p_to,
         started_at=case when p_to='RUNNING' and started_at is null then now() else started_at end,
         finished_at=case when p_to in ('COMPLETED','FAILED','CANCELLED') then now() else finished_at end
   where id=r.id
   returning * into r;
  return r;
end;
$$;

create or replace function public.ai_transition_node_run(
  p_node_run_id uuid,
  p_to text,
  p_reason text default null,
  p_actor text default 'system'
) returns public.ai_node_runs
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_node_runs;
begin
  select * into r from public.ai_node_runs
   where id=p_node_run_id for update;
  if not found then raise exception 'node_run_not_found'; end if;
  if not public.ai_assert_node_transition(r.state,p_to) then
    raise exception 'invalid_node_transition:%->%',r.state,p_to;
  end if;

  update public.ai_node_runs
     set state=p_to,
         started_at=case when p_to='RUNNING' and started_at is null then now() else started_at end,
         finished_at=case when p_to in ('COMPLETED','FAILED','SKIPPED','TIMEOUT','CANCELLED') then now() else finished_at end,
         error=case when p_reason is not null and p_to in ('FAILED','TIMEOUT') then jsonb_build_object('reason',left(p_reason,1000)) else error end
   where id=r.id
   returning * into r;
  return r;
end;
$$;

create or replace function public.ai_transition_tool_run(
  p_tool_run_id uuid,
  p_to text,
  p_reason text default null,
  p_actor text default 'system'
) returns public.ai_tool_runs
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_tool_runs;
begin
  select * into r from public.ai_tool_runs
   where id=p_tool_run_id for update;
  if not found then raise exception 'tool_run_not_found'; end if;
  if not public.ai_assert_tool_transition(r.state,p_to) then
    raise exception 'invalid_tool_transition:%->%',r.state,p_to;
  end if;

  update public.ai_tool_runs
     set state=p_to,
         finished_at=case when p_to in ('COMPLETED','FAILED','TIMEOUT','CANCELLED') then now() else finished_at end,
         error=case when p_reason is not null and p_to in ('FAILED','TIMEOUT','BLOCKED') then jsonb_build_object('reason',left(p_reason,1000)) else error end
   where id=r.id
   returning * into r;
  return r;
end;
$$;

-- Worker claim is the only authoritative way to move a queued node into RUNNING.
-- FOR UPDATE SKIP LOCKED prevents two workers from owning the same attempt.
create or replace function public.ai_claim_node_run(
  p_worker_id text,
  p_tenant_id uuid default null
) returns public.ai_node_runs
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare r public.ai_node_runs;
begin
  if p_worker_id is null or length(trim(p_worker_id))=0 or length(p_worker_id)>128 then
    raise exception 'invalid_worker_id';
  end if;

  select nr.* into r
    from public.ai_node_runs nr
    join public.ai_mission_runs mr on mr.id=nr.mission_run_id
    join public.ai_runs ar on ar.id=mr.run_id
   where nr.state='QUEUED'
     and (nr.next_retry_at is null or nr.next_retry_at <= now())
     and mr.state in ('QUEUED','RUNNING')
     and ar.run_state in ('QUEUED','RUNNING','RECOVERING')
     and (p_tenant_id is null or nr.tenant_id=p_tenant_id)
   order by coalesce(nr.next_retry_at,nr.created_at),nr.created_at
   for update of nr skip locked
   limit 1;

  if not found then return null; end if;

  update public.ai_node_runs
     set state='RUNNING',
         started_at=coalesce(started_at,now())
   where id=r.id
   returning * into r;

  return r;
end;
$$;

-- Reconcile node completion into mission progress without allowing a worker to
-- fabricate tenant/run ownership.
create or replace function public.ai_record_node_completion(
  p_node_run_id uuid,
  p_success boolean,
  p_output_hash text default null
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_temp
as $$
declare
  n public.ai_node_runs;
  m public.ai_mission_runs;
  total integer;
  done integer;
begin
  select * into n from public.ai_node_runs where id=p_node_run_id for update;
  if not found then raise exception 'node_run_not_found'; end if;

  if p_success then
    n := public.ai_transition_node_run(p_node_run_id,'COMPLETED');
    update public.ai_node_runs set output_hash=p_output_hash where id=n.id;
  else
    n := public.ai_transition_node_run(p_node_run_id,'FAILED','worker reported failure');
  end if;

  select * into m from public.ai_mission_runs where id=n.mission_run_id for update;

  select count(*) into total
    from public.ai_node_runs where mission_run_id=m.id and attempt=1;
  select count(*) into done
    from public.ai_node_runs where mission_run_id=m.id and state in ('COMPLETED','SKIPPED');

  update public.ai_mission_runs
     set node_count=greatest(node_count,total),
         completed_nodes=done
   where id=m.id;

  if total > 0 and done=total then
    m := public.ai_transition_mission_run(m.id,'COMPLETED','all nodes complete');
    perform public.ai_transition_run(m.run_id,'COMPLETED','mission_complete','system');
  end if;

  return jsonb_build_object(
    'mission_run_id',m.id,
    'completed_nodes',done,
    'node_count',total,
    'mission_state',(select state from public.ai_mission_runs where id=m.id)
  );
end;
$$;

do $$
declare f record;
begin
  for f in select * from (values
    ('ai_assert_mission_transition(text,text)'),
    ('ai_assert_node_transition(text,text)'),
    ('ai_assert_tool_transition(text,text)'),
    ('ai_transition_mission_run(uuid,text,text,text)'),
    ('ai_transition_node_run(uuid,text,text,text)'),
    ('ai_transition_tool_run(uuid,text,text,text)'),
    ('ai_claim_node_run(text,uuid)'),
    ('ai_record_node_completion(uuid,boolean,text)')
  ) x(signature)
  loop
    execute 'revoke all on function public.'||f.signature||' from public,anon,authenticated';
  end loop;
end $$;

grant execute on function public.ai_assert_mission_transition(text,text) to service_role;
grant execute on function public.ai_assert_node_transition(text,text) to service_role;
grant execute on function public.ai_assert_tool_transition(text,text) to service_role;
grant execute on function public.ai_transition_mission_run(uuid,text,text,text) to service_role;
grant execute on function public.ai_transition_node_run(uuid,text,text,text) to service_role;
grant execute on function public.ai_transition_tool_run(uuid,text,text,text) to service_role;
grant execute on function public.ai_claim_node_run(text,uuid) to service_role;
grant execute on function public.ai_record_node_completion(uuid,boolean,text) to service_role;

comment on function public.ai_claim_node_run is
'Crash-safe worker claim boundary. SKIP LOCKED ensures a node attempt has one active worker owner.';
