-- 097_atomic_device_command_execution.sql
-- Close the remaining device-result race: command terminalization and
-- canonical AI execution settlement/release happen in one transaction.
-- Device identity is supplied by the already-authenticated API boundary;
-- run identity is always derived from the locked command row.

create or replace function public.ai_complete_device_command_result(
  p_device_id uuid,
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
  v_cost numeric(18,8) := 0;
  v_completion jsonb;
begin
  if p_device_id is null
     or p_command_id is null
     or p_status not in ('success','failed') then
    raise exception 'invalid_device_command_result';
  end if;

  select * into c
    from public.commands
   where id=p_command_id
     and device_id=p_device_id
   for update;

  if not found then
    raise exception 'device_command_not_found';
  end if;

  -- A terminal retry must exactly match the durable outcome. It is allowed
  -- to re-enter the canonical AI completion boundary idempotently.
  if c.status in ('success','failed') then
    if c.status <> p_status then
      raise exception 'command_outcome_mismatch';
    end if;

    if c.ai_run_id is null then
      return jsonb_build_object(
        'accepted',false,
        'idempotent',true,
        'ai_bound',false,
        'command_id',c.id
      );
    end if;

    v_outcome := case when p_status='success' then 'COMPLETED' else 'FAILED' end;
    v_cost := case
      when p_status='success'
       and p_result is not null
       and (p_result->>'cost_usd') ~ '^[0-9]+(\.[0-9]{1,8})?$'
      then (p_result->>'cost_usd')::numeric(18,8)
      else 0
    end;

    v_completion := public.ai_complete_execution(
      c.ai_run_id,
      v_outcome,
      v_cost,
      case when p_status='failed'
        then jsonb_build_object(
          'command_id',c.id,
          'error',coalesce(p_error,'device_command_failed'),
          'result',coalesce(p_result,'{}'::jsonb)
        )
        else null
      end,
      left(coalesce(p_actor,'device'),128)
    );

    return v_completion || jsonb_build_object(
      'accepted',false,
      'idempotent',true,
      'command_id',c.id
    );
  end if;

  -- Only a command that has not already reached a terminal state can be
  -- transitioned by the device. Expired/revoked/other terminal states fail.
  if c.status not in ('pending','claimed','running','issued') then
    raise exception 'command_not_completable';
  end if;

  update public.commands
     set status=p_status,
         completed_at=now(),
         outcome=p_status,
         outcome_error=case
           when p_status='failed'
           then jsonb_build_object(
             'error',coalesce(p_error,'device_command_failed'),
             'result',coalesce(p_result,'{}'::jsonb)
           )
           else null
         end
   where id=c.id
   returning * into c;

  if c.ai_run_id is null then
    return jsonb_build_object(
      'accepted',true,
      'idempotent',false,
      'ai_bound',false,
      'command_id',c.id,
      'status',c.status
    );
  end if;

  v_outcome := case when p_status='success' then 'COMPLETED' else 'FAILED' end;
  v_cost := case
    when p_status='success'
     and p_result is not null
     and (p_result->>'cost_usd') ~ '^[0-9]+(\.[0-9]{1,8})?$'
    then (p_result->>'cost_usd')::numeric(18,8)
    else 0
  end;

  v_completion := public.ai_complete_execution(
    c.ai_run_id,
    v_outcome,
    v_cost,
    case when p_status='failed'
      then jsonb_build_object(
        'command_id',c.id,
        'error',coalesce(p_error,'device_command_failed'),
        'result',coalesce(p_result,'{}'::jsonb)
      )
      else null
    end,
    left(coalesce(p_actor,'device'),128)
  );

  return v_completion || jsonb_build_object(
    'accepted',true,
    'idempotent',false,
    'command_id',c.id,
    'status',c.status
  );
end;
$$;

revoke all on function public.ai_complete_device_command_result(
  uuid,uuid,text,jsonb,text,text
) from public,anon,authenticated;
grant execute on function public.ai_complete_device_command_result(
  uuid,uuid,text,jsonb,text,text
) to service_role;

comment on function public.ai_complete_device_command_result is
'Atomic device command terminalization plus canonical AI execution outcome. Command/run identity and tenant are derived from the locked command row; client result never supplies run identity.';
