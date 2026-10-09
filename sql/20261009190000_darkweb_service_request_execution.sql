-- Cyclothone customer service-request execution lifecycle.
-- Additive and idempotent; deploy with the API/worker code in the same release.
alter table public.service_requests
  add column if not exists target text,
  add column if not exists target_type text,
  add column if not exists processing_state text not null default 'queued',
  add column if not exists attempts integer not null default 0,
  add column if not exists locked_until timestamptz,
  add column if not exists started_at timestamptz,
  add column if not exists completed_at timestamptz,
  add column if not exists failure_code text,
  add column if not exists result jsonb;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'service_requests_target_type_check') then
    alter table public.service_requests add constraint service_requests_target_type_check
      check (target_type is null or target_type in ('domain','url','email','brand','username','ip','other'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'service_requests_processing_state_check') then
    alter table public.service_requests add constraint service_requests_processing_state_check
      check (processing_state in ('queued','running','succeeded','failed','blocked'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'service_requests_attempts_check') then
    alter table public.service_requests add constraint service_requests_attempts_check check (attempts >= 0);
  end if;
end $$;

create index if not exists service_requests_claim_idx
  on public.service_requests (service_key, created_at)
  where processing_state in ('queued','running');

create or replace function public.claim_service_requests(
  p_service_key text, p_limit integer default 5, p_lease_seconds integer default 120
) returns setof public.service_requests
language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if p_service_key is null or p_service_key = '' or p_limit < 1 or p_limit > 25
     or p_lease_seconds < 15 or p_lease_seconds > 900 then
    raise exception 'invalid_claim_parameters';
  end if;
  return query
  with candidates as (
    select id
      from public.service_requests
     where service_key = p_service_key
       and attempts < 3
       and (processing_state = 'queued'
         or (processing_state = 'running' and locked_until is not null and locked_until < now()))
     order by created_at
     for update skip locked
     limit p_limit
  )
  update public.service_requests r
     set processing_state = 'running',
         status = case when r.status = 'submitted' then 'triage' else r.status end,
         attempts = r.attempts + 1,
         locked_until = now() + make_interval(secs => p_lease_seconds),
         started_at = coalesce(r.started_at, now()),
         updated_at = now()
    from candidates c
   where r.id = c.id
  returning r.*;
end $$;

create or replace function public.complete_service_request(
  p_id uuid, p_state text, p_status text, p_result jsonb, p_failure_code text default null
) returns void
language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  if p_state not in ('succeeded','failed','blocked') then
    raise exception 'invalid_processing_state';
  end if;
  update public.service_requests
     set processing_state = p_state,
         status = p_status,
         result = coalesce(p_result, '{}'::jsonb),
         failure_code = p_failure_code,
         locked_until = null,
         updated_at = now(),
         completed_at = now()
   where id = p_id;
  if not found then raise exception 'service_request_not_found'; end if;
end $$;

create or replace function public.sweep_expired_service_requests()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare changed integer;
begin
  update public.service_requests
     set processing_state = 'failed',
         status = 'blocked',
         failure_code = 'max_attempts',
         locked_until = null,
         completed_at = coalesce(completed_at, now()),
         updated_at = now()
   where processing_state = 'running'
     and attempts >= 3
     and locked_until is not null
     and locked_until < now();
  get diagnostics changed = row_count;
  return changed;
end $$;

revoke all on function public.claim_service_requests(text,integer,integer) from public, anon, authenticated;
revoke all on function public.complete_service_request(uuid,text,text,jsonb,text) from public, anon, authenticated;
revoke all on function public.sweep_expired_service_requests() from public, anon, authenticated;
grant execute on function public.claim_service_requests(text,integer,integer) to service_role;
grant execute on function public.complete_service_request(uuid,text,text,jsonb,text) to service_role;
grant execute on function public.sweep_expired_service_requests() to service_role;
