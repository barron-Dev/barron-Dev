-- Durable per-source checkpoints for resumable Dark Web requests.
-- Deploy with the matching worker. This migration does not alter live data until applied.

create table if not exists public.service_request_execution_checkpoints (
  service_request_id uuid primary key
    references public.service_requests(id) on delete cascade,
  checkpoint jsonb not null default '{"version":1,"sources":{}}'::jsonb,
  updated_at timestamptz not null default now(),
  constraint service_request_execution_checkpoints_object_check
    check (jsonb_typeof(checkpoint) = 'object')
);

alter table public.service_request_execution_checkpoints enable row level security;
revoke all on table public.service_request_execution_checkpoints from public, anon, authenticated;
grant select on table public.service_request_execution_checkpoints to service_role;

create or replace function public.checkpoint_service_request(
  p_id uuid,
  p_attempt integer,
  p_checkpoint jsonb,
  p_lease_seconds integer default 180
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  claimed_id uuid;
begin
  if p_attempt < 1
     or p_checkpoint is null
     or jsonb_typeof(p_checkpoint) <> 'object'
     or pg_column_size(p_checkpoint) > 1048576
     or p_lease_seconds < 15
     or p_lease_seconds > 900 then
    raise exception 'invalid_checkpoint_parameters';
  end if;

  update public.service_requests
     set locked_until = now() + make_interval(secs => p_lease_seconds),
         updated_at = now()
   where id = p_id
     and processing_state = 'running'
     and attempts = p_attempt
     and locked_until is not null
     and locked_until > now()
  returning id into claimed_id;

  if claimed_id is null then
    return false;
  end if;

  insert into public.service_request_execution_checkpoints (
    service_request_id, checkpoint, updated_at
  ) values (
    p_id, p_checkpoint, now()
  )
  on conflict (service_request_id) do update
    set checkpoint = excluded.checkpoint,
        updated_at = excluded.updated_at;

  return true;
end
$$;

-- Preserve the release's attempt/lease fence and remove private checkpoint state
-- atomically with terminal completion. The final customer result remains in
-- service_requests.result and never contains the intermediate checkpoint.
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
declare
  completed boolean;
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

  completed := found;
  if completed then
    delete from public.service_request_execution_checkpoints
     where service_request_id = p_id;
  end if;
  return completed;
end
$$;

revoke all on function public.checkpoint_service_request(uuid,integer,jsonb,integer) from public, anon, authenticated;
revoke all on function public.complete_service_request(uuid,integer,text,text,jsonb,text) from public, anon, authenticated;
grant execute on function public.checkpoint_service_request(uuid,integer,jsonb,integer) to service_role;
grant execute on function public.complete_service_request(uuid,integer,text,text,jsonb,text) to service_role;
