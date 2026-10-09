-- Cyclothone Dark Web completion fencing.
-- Deploy with the matching worker/API release; do not apply independently.
-- Drop the prior overload so calls cannot resolve to the unfenced RPC.
drop function if exists public.complete_service_request(uuid,text,text,jsonb,text);

create or replace function public.complete_service_request(
  p_id uuid,
  p_attempt integer,
  p_state text,
  p_status text,
  p_result jsonb,
  p_failure_code text default null
) returns boolean
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
   where id = p_id
     and processing_state = 'running'
     and attempts = p_attempt
     and locked_until is not null
     and locked_until > now();

  return found;
end $$;

revoke all on function public.complete_service_request(uuid,integer,text,text,jsonb,text) from public, anon, authenticated;
grant execute on function public.complete_service_request(uuid,integer,text,text,jsonb,text) to service_role;
