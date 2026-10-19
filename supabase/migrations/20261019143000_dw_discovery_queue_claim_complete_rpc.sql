-- Atomic queue claiming and lease-fenced completion.
-- Review-only migration: do not apply to production until the worker is reviewed.
begin;

create or replace function public.claim_dw_source_discovery_jobs(
  p_limit integer default 25,
  p_lease_seconds integer default 120
)
returns table (
  job_id bigint,
  scope_key text,
  category_slug text,
  discovery_kind text,
  candidate_url text,
  candidate_host text,
  discovery_provenance text,
  language_code text,
  religion_slug text,
  attempt_count integer,
  lease_token uuid,
  lease_expires_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $function$
begin
  if p_limit is null or p_limit < 1 or p_limit > 100 then
    raise exception 'p_limit must be between 1 and 100';
  end if;
  if p_lease_seconds is null or p_lease_seconds < 30 or p_lease_seconds > 900 then
    raise exception 'p_lease_seconds must be between 30 and 900';
  end if;

  return query
  with eligible as (
    select q.id
    from public.dw_source_discovery_queue q
    where (q.queue_status = 'queued' and coalesce(q.next_attempt_at, now()) <= now())
       or (q.queue_status = 'processing' and q.lease_expires_at < now())
    order by q.created_at, q.id
    for update skip locked
    limit p_limit
  ), claimed as (
    update public.dw_source_discovery_queue q
    set queue_status = 'processing',
        lease_token = gen_random_uuid(),
        lease_expires_at = now() + make_interval(secs => p_lease_seconds),
        attempt_count = coalesce(q.attempt_count, 0) + 1,
        updated_at = now()
    from eligible e
    where q.id = e.id
    returning q.*
  )
  select c.id, c.scope_key, c.category_slug, c.discovery_kind,
         c.candidate_url, c.candidate_host, c.discovery_provenance,
         c.language_code, c.religion_slug, c.attempt_count,
         c.lease_token, c.lease_expires_at
  from claimed c;
end;
$function$;

create or replace function public.complete_dw_source_discovery_job(
  p_job_id bigint,
  p_lease_token uuid,
  p_outcome text,
  p_error_code text default null,
  p_result_metadata jsonb default '{}'::jsonb,
  p_retry_after_seconds integer default 300,
  p_max_attempts integer default 6
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $function$
declare
  v_rows integer;
  v_outcome text := p_outcome;
begin
  if p_outcome not in ('completed', 'retry', 'dead_letter') then
    raise exception 'unsupported outcome';
  end if;
  if p_retry_after_seconds is null or p_retry_after_seconds < 30 or p_retry_after_seconds > 86400 then
    raise exception 'p_retry_after_seconds must be between 30 and 86400';
  end if;
  if p_max_attempts is null or p_max_attempts < 1 or p_max_attempts > 20 then
    raise exception 'p_max_attempts must be between 1 and 20';
  end if;

  -- A retry budget exhaustion is terminal. The caller cannot revive a job
  -- merely by presenting an old token; the active lease must still match.
  if p_outcome = 'retry' then
    update public.dw_source_discovery_queue q
    set queue_status = case when coalesce(q.attempt_count, 0) >= p_max_attempts
                            then 'dead_letter' else 'queued' end,
        last_error_code = left(coalesce(p_error_code, 'retry_requested'), 120),
        result_metadata = coalesce(q.result_metadata, '{}'::jsonb) || coalesce(p_result_metadata, '{}'::jsonb),
        next_attempt_at = case when coalesce(q.attempt_count, 0) >= p_max_attempts
                               then null else now() + make_interval(secs => p_retry_after_seconds) end,
        dead_lettered_at = case when coalesce(q.attempt_count, 0) >= p_max_attempts
                                then now() else q.dead_lettered_at end,
        lease_token = null,
        lease_expires_at = null,
        updated_at = now()
    where q.id = p_job_id and q.queue_status = 'processing'
      and q.lease_token = p_lease_token and q.lease_expires_at >= now();
  else
    update public.dw_source_discovery_queue q
    set queue_status = case when v_outcome = 'completed' then 'completed' else 'dead_letter' end,
        last_error_code = case when v_outcome = 'completed' then null else left(coalesce(p_error_code, 'dead_lettered'), 120) end,
        result_metadata = coalesce(q.result_metadata, '{}'::jsonb) || coalesce(p_result_metadata, '{}'::jsonb),
        next_attempt_at = null,
        completed_at = case when v_outcome = 'completed' then now() else q.completed_at end,
        dead_lettered_at = case when v_outcome = 'dead_letter' then now() else q.dead_lettered_at end,
        lease_token = null,
        lease_expires_at = null,
        updated_at = now()
    where q.id = p_job_id and q.queue_status = 'processing'
      and q.lease_token = p_lease_token and q.lease_expires_at >= now();
  end if;

  get diagnostics v_rows = row_count;
  return v_rows = 1;
end;
$function$;

revoke all on function public.claim_dw_source_discovery_jobs(integer, integer) from public, anon, authenticated;
revoke all on function public.complete_dw_source_discovery_job(bigint, uuid, text, text, jsonb, integer, integer) from public, anon, authenticated;
grant execute on function public.claim_dw_source_discovery_jobs(integer, integer) to service_role;
grant execute on function public.complete_dw_source_discovery_job(bigint, uuid, text, text, jsonb, integer, integer) to service_role;

commit;
