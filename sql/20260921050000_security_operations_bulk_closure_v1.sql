-- Security Operations bulk closure: threat-intelligence, investigation and case-control boundaries.
-- Reuses existing intel_feeds, indicators, investigation_sessions and crime_cases.
-- No parallel case or intelligence store is introduced.

create index if not exists indicators_tenant_type_value_idx
  on public.indicators(tenant_id, ioc_type, value);

create index if not exists indicators_active_expiry_idx
  on public.indicators(tenant_id, expires_at)
  where expires_at is null or expires_at > now();

create index if not exists intel_feeds_enabled_idx
  on public.intel_feeds(tenant_id, enabled, last_pull_at);

create index if not exists investigation_sessions_active_idx
  on public.investigation_sessions(tenant_id, status, updated_at)
  where status in ('requested','approved','running');

create index if not exists crime_cases_tenant_status_idx
  on public.crime_cases(tenant_id, status, updated_at desc);

create or replace function public.complete_investigation_session(
  p_session_id uuid,
  p_tenant_id uuid,
  p_actor text,
  p_summary text default null
) returns uuid
language plpgsql
security definer
set search_path=public,pg_temp
as $function$
declare
  v_case_id uuid;
  v_updated uuid;
begin
  update public.investigation_sessions
     set status='completed',
         completed_at=now(),
         updated_at=now()
   where id=p_session_id
     and tenant_id=p_tenant_id
     and status='running'
   returning id, case_id into v_updated, v_case_id;

  if v_updated is null then
    raise exception 'investigation_session_not_running';
  end if;

  insert into public.investigation_events(tenant_id,session_id,event_type,event_at,actor,payload)
  values (
    p_tenant_id,p_session_id,'completed',now(),p_actor,
    jsonb_build_object('summary',nullif(left(coalesce(p_summary,''),4000),''))
  );

  if v_case_id is not null then
    insert into public.case_timeline(case_id,actor,kind,payload)
    values (
      v_case_id,p_actor,'investigation_completed',
      jsonb_build_object('session_id',p_session_id,'summary',nullif(left(coalesce(p_summary,''),4000),''))
    );
  end if;

  return p_session_id;
end
$function$;

revoke all on function public.complete_investigation_session(uuid,uuid,text,text) from public,anon,authenticated;
grant execute on function public.complete_investigation_session(uuid,uuid,text,text) to service_role;

create or replace function public.transition_security_case(
  p_case_id uuid,
  p_tenant_id uuid,
  p_to_status text,
  p_actor text,
  p_reason text default null
) returns uuid
language plpgsql
security definer
set search_path=public,pg_temp
as $function$
declare
  v_from text;
begin
  if p_to_status not in ('open','in_progress','resolved','closed') then
    raise exception 'invalid_case_status';
  end if;

  select status into v_from
    from public.crime_cases
   where id=p_case_id and tenant_id=p_tenant_id
   for update;

  if v_from is null then
    raise exception 'case_not_found';
  end if;

  if v_from=p_to_status then
    return p_case_id;
  end if;

  if v_from='closed' then
    raise exception 'closed_case_is_terminal';
  end if;

  if v_from='open' and p_to_status not in ('in_progress','resolved','closed') then
    raise exception 'invalid_case_transition';
  elsif v_from='in_progress' and p_to_status not in ('resolved','open') then
    raise exception 'invalid_case_transition';
  elsif v_from='resolved' and p_to_status not in ('closed','in_progress') then
    raise exception 'invalid_case_transition';
  end if;

  update public.crime_cases
     set status=p_to_status, updated_at=now()
   where id=p_case_id and tenant_id=p_tenant_id;

  insert into public.case_timeline(case_id,actor,kind,payload)
  values (
    p_case_id,p_actor,'status_transition',
    jsonb_build_object(
      'from',v_from,
      'to',p_to_status,
      'reason',nullif(left(coalesce(p_reason,''),4000),'')
    )
  );

  return p_case_id;
end
$function$;

revoke all on function public.transition_security_case(uuid,uuid,text,text,text) from public,anon,authenticated;
grant execute on function public.transition_security_case(uuid,uuid,text,text,text) to service_role;
