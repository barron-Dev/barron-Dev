-- 090_device_result_execution_bridge.sql
-- Bridge device command completion into the canonical AI execution outcome.
-- Device authentication remains the command-authority boundary; this function
-- only settles a command's already-bound AI run.

create or replace function public.ai_complete_device_command_execution(
  p_command_id uuid,
  p_status text,
  p_result jsonb default null,
  p_error text default null,
  p_actor text default 'device'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  c public.commands;
  v_outcome text;
  v_cost numeric(18,8);
begin
  if p_command_id is null or p_status not in ('success','failed') then
    raise exception 'invalid_command_execution_outcome';
  end if;

  select * into c
    from public.commands
   where id = p_command_id
   for update;

  if not found then
    raise exception 'command_not_found';
  end if;

  if c.status not in ('success','failed') then
    raise exception 'command_not_terminal';
  end if;

  if c.status <> p_status then
    raise exception 'command_outcome_mismatch';
  end if;

  if c.ai_run_id is null then
    return jsonb_build_object(
      'completed',false,
      'ai_bound',false,
      'command_id',c.id
    );
  end if;

  v_outcome := case when p_status = 'success' then 'COMPLETED' else 'FAILED' end;
  v_cost := case
    when p_status = 'success'
      and p_result is not null
      and (p_result->>'cost_usd') ~ '^[0-9]+(\.[0-9]{1,8})?$'
      then (p_result->>'cost_usd')::numeric(18,8)
    else 0
  end;

  return public.ai_complete_execution(
    c.ai_run_id,
    v_outcome,
    v_cost,
    case
      when p_status = 'failed'
        then jsonb_build_object('command_id',c.id,'error',coalesce(p_error,'device_command_failed'),'result',coalesce(p_result,'{}'::jsonb))
      else null
    end,
    left(p_actor,128)
  );
end;
$$;

revoke all on function public.ai_complete_device_command_execution(
  uuid,text,jsonb,text,text
) from public,anon,authenticated;
grant execute on function public.ai_complete_device_command_execution(
  uuid,text,jsonb,text,text
) to service_role;

comment on function public.ai_complete_device_command_execution is
'Bridges authenticated device command results to the canonical AI execution settlement/release boundary without trusting client run identity or cost.';
