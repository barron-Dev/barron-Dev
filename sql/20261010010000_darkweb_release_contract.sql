-- Cyclothone Dark Web production release contract.
-- This migration intentionally installs the exact fenced completion signature
-- required by src/cyclothone/darkweb/request_worker.py. Apply only in the same
-- controlled release as the matching API/worker code.
--
-- Idempotent final compatibility layer: removes both known unfenced signatures
-- so PostgREST cannot resolve an old completion function after this migration.

alter table public.service_requests
  add column if not exists processing_state text not null default 'queued',
  add column if not exists attempts integer not null default 0,
  add column if not exists locked_until timestamptz,
  add column if not exists started_at timestamptz,
  add column if not exists completed_at timestamptz,
  add column if not exists failure_code text,
  add column if not exists result jsonb,
  add column if not exists target text,
  add column if not exists target_type text;

drop function if exists public.complete_service_request(uuid,text,text,jsonb,text);
drop function if exists public.complete_service_request(uuid,integer,text,text,jsonb,text);

create or replace function public.complete_service_request(
  p_id uuid,
  p_attempt integer,
  p_state text,
  p_status text,
  p_result jsonb,
  p_failure_code text default null
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
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
   where id = p_id
     and processing_state = 'running'
     and attempts = p_attempt
     and locked_until is not null
     and locked_until > now();

  return found;
end
$$;

create or replace function public.sweep_expired_service_requests()
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
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
end
$$;

revoke all on function public.complete_service_request(uuid,integer,text,text,jsonb,text) from public, anon, authenticated;
revoke all on function public.sweep_expired_service_requests() from public, anon, authenticated;
grant execute on function public.complete_service_request(uuid,integer,text,text,jsonb,text) to service_role;
grant execute on function public.sweep_expired_service_requests() to service_role;
