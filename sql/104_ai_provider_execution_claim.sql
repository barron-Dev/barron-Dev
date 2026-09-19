-- Canonical provider execution claim boundary.
-- Prevents duplicate provider calls for the same authorized AI run.

create or replace function public.ai_assert_transition(p_from text, p_to text)
returns boolean
language sql
immutable strict
as $function$
  select case p_from
    when 'REQUESTED' then p_to in ('QUEUED','REJECTED','CANCELLED')
    when 'QUEUED' then p_to in ('RUNNING','CANCELLED','TIMEOUT','REJECTED')
    when 'AUTHORIZED' then p_to in ('RUNNING','REJECTED','CANCELLED','TIMEOUT','STUCK')
    when 'RUNNING' then p_to in ('STREAMING','WAITING_APPROVAL','COMPLETED','FAILED','TIMEOUT','CANCELLED','STUCK')
    when 'STREAMING' then p_to in ('RUNNING','COMPLETED','FAILED','TIMEOUT','CANCELLED','STUCK')
    when 'WAITING_APPROVAL' then p_to in ('RUNNING','REJECTED','CANCELLED','TIMEOUT','STUCK')
    when 'STUCK' then p_to in ('RECOVERING','FAILED','CANCELLED')
    when 'RECOVERING' then p_to in ('QUEUED','RUNNING','FAILED','CANCELLED')
    else false
  end
$function$;

create or replace function public.ai_claim_provider_execution(
  p_run_id uuid,
  p_actor text default 'ai_provider'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $function$
declare
  r public.ai_runs;
  v_lease boolean;
begin
  if p_run_id is null then
    raise exception 'run_id_required';
  end if;

  select * into r
    from public.ai_runs
   where id = p_run_id
   for update;

  if not found then
    raise exception 'run_not_found';
  end if;

  if r.run_state <> 'AUTHORIZED' then
    return jsonb_build_object(
      'claimed',false,
      'run_id',r.id,
      'run_state',r.run_state,
      'reason',case
        when r.run_state in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED')
          then 'finalized'
        else 'already_claimed'
      end
    );
  end if;

  select exists (
    select 1
      from public.ai_admission_leases
     where run_id = r.id
       and released_at is null
       and expires_at > now()
  ) into v_lease;

  if not v_lease then
    raise exception 'execution_lease_missing_or_expired';
  end if;

  if not exists (
    select 1
      from public.ai_execution_provenance
     where run_id = r.id
  ) then
    raise exception 'execution_not_committed';
  end if;

  perform public.ai_transition_run(
    r.id,
    'RUNNING',
    'provider_execution_claim',
    left(coalesce(p_actor,'ai_provider'),128)
  );

  return jsonb_build_object(
    'claimed',true,
    'run_id',r.id,
    'run_state','RUNNING',
    'claimed_at',now()
  );
end;
$function$;

revoke all on function public.ai_claim_provider_execution(uuid,text)
  from public,anon,authenticated;
grant execute on function public.ai_claim_provider_execution(uuid,text)
  to service_role;
