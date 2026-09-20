begin;

-- Reconcile the continuous trust worker's SECURITY DEFINER boundary.
-- Supabase documents auth.role() as deprecated; privileged worker RPCs
-- must bind execution to the database service role instead.
create or replace function public.trust_claim_re_evaluation(p_limit integer default 25)
returns setof public.trust_re_evaluation_queue
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  if current_user <> 'service_role' then
    raise exception 'service_role_required';
  end if;
  if p_limit < 1 or p_limit > 100 then
    raise exception 'invalid_claim_limit';
  end if;
  update public.trust_re_evaluation_queue
     set status='PENDING', locked_at=null,
         last_error=coalesce(last_error,'stale_processing_reclaimed')
   where status='PROCESSING'
     and locked_at < now()-interval '5 minutes';
  return query
  with claimed as (
    select q.id
      from public.trust_re_evaluation_queue q
     where q.status='PENDING' and q.available_at<=now()
     order by q.created_at
     for update skip locked
     limit p_limit
  )
  update public.trust_re_evaluation_queue q
     set status='PROCESSING', attempts=q.attempts+1, locked_at=now()
    from claimed c
   where q.id=c.id
  returning q.*;
end;
$$;

create or replace function public.trust_complete_re_evaluation(
  p_queue_id uuid,
  p_success boolean,
  p_result jsonb default '{}'::jsonb,
  p_error text default null
)
returns public.trust_re_evaluation_queue
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare q public.trust_re_evaluation_queue; v_delay interval;
begin
  if current_user <> 'service_role' then
    raise exception 'service_role_required';
  end if;
  select * into q from public.trust_re_evaluation_queue where id=p_queue_id for update;
  if not found then raise exception 'trust_re_evaluation_job_not_found'; end if;
  if q.status <> 'PROCESSING' then raise exception 'trust_re_evaluation_job_not_processing'; end if;
  if p_success then
    update public.trust_re_evaluation_queue
       set status='COMPLETED', completed_at=now(), locked_at=null,
           last_error=null, result=coalesce(p_result,'{}'::jsonb)
     where id=q.id returning * into q;
  else
    v_delay := least(interval '15 minutes',
      interval '30 seconds' * power(2::numeric,greatest(q.attempts-1,0)));
    if q.attempts >= 8 then
      update public.trust_re_evaluation_queue
         set status='FAILED', completed_at=null, locked_at=null,
             last_error=coalesce(p_error,'reevaluation_failed'),
             result=coalesce(p_result,'{}'::jsonb)
       where id=q.id returning * into q;
    else
      update public.trust_re_evaluation_queue
         set status='PENDING', completed_at=null, locked_at=null,
             available_at=now()+v_delay,
             last_error=coalesce(p_error,'reevaluation_failed'),
             result=coalesce(p_result,'{}'::jsonb)
       where id=q.id returning * into q;
    end if;
  end if;
  return q;
end;
$$;

create or replace function public.trust_worker_heartbeat(
  p_worker_name text,
  p_status text,
  p_success boolean default false,
  p_error_code text default null,
  p_metadata jsonb default '{}'::jsonb
)
returns void
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
begin
  if current_user <> 'service_role' then raise exception 'service_role_required'; end if;
  insert into public.trust_worker_heartbeats(
    worker_name,status,last_heartbeat_at,last_success_at,last_error_at,last_error_code,metadata)
  values(
    p_worker_name,p_status,now(),
    case when p_success then now() end,
    case when p_error_code is not null then now() end,
    p_error_code,coalesce(p_metadata,'{}'::jsonb))
  on conflict(worker_name) do update set
    status=excluded.status,last_heartbeat_at=excluded.last_heartbeat_at,
    last_success_at=case when p_success then now() else trust_worker_heartbeats.last_success_at end,
    last_error_at=case when p_error_code is not null then now() else trust_worker_heartbeats.last_error_at end,
    last_error_code=case when p_error_code is not null then p_error_code else trust_worker_heartbeats.last_error_code end,
    metadata=excluded.metadata;
end;
$$;

revoke all on function public.trust_claim_re_evaluation(integer) from public, anon, authenticated;
revoke all on function public.trust_complete_re_evaluation(uuid,boolean,jsonb,text) from public, anon, authenticated;
revoke all on function public.trust_worker_heartbeat(text,text,boolean,text,jsonb) from public, anon, authenticated;
grant execute on function public.trust_claim_re_evaluation(integer) to service_role;
grant execute on function public.trust_complete_re_evaluation(uuid,boolean,jsonb,text) to service_role;
grant execute on function public.trust_worker_heartbeat(text,text,boolean,text,jsonb) to service_role;

commit;