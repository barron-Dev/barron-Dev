-- Response execution hardening: atomic blast-radius checks, expiry reconciliation, and terminal result idempotency.
create or replace function public.check_blast_radius_scoped(
  p_rule_id uuid,
  p_tenant_id uuid,
  p_device_id uuid,
  p_limit integer,
  p_window_minutes integer default 60
) returns boolean
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_count integer;
begin
  if p_rule_id is null or p_tenant_id is null or p_device_id is null
     or p_limit < 1 or p_window_minutes < 1 then
    return false;
  end if;

  select count(distinct device_id) into v_count
    from public.rule_blast_log
   where rule_id = p_rule_id
     and tenant_id = p_tenant_id
     and ts >= now() - (p_window_minutes || ' minutes')::interval;

  return v_count < p_limit;
end;
$$;

revoke all on function public.check_blast_radius_scoped(uuid,uuid,uuid,integer,integer) from public, anon, authenticated;
grant execute on function public.check_blast_radius_scoped(uuid,uuid,uuid,integer,integer) to service_role;

create or replace function public.claim_device_commands(p_device_id uuid, p_limit integer default 10)
returns setof public.commands
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_limit < 1 or p_limit > 50 then
    raise exception 'invalid command batch size';
  end if;

  if not exists (
    select 1 from public.devices d
    where d.id = p_device_id
      and d.status = 'active'
      and d.cert_fingerprint is not null
  ) then
    raise exception 'device not authorized';
  end if;

  update public.commands c
     set status = 'failed',
         executed_at = now(),
         error = 'command expired before execution'
   where c.device_id = p_device_id
     and c.status = 'pending'
     and c.expires_at <= now();

  return query
  with claimed as (
    select c.id
      from public.commands c
     where c.device_id = p_device_id
       and c.status = 'pending'
       and c.delivered_at is null
       and c.expires_at > now()
     order by c.issued_at
     for update skip locked
     limit p_limit
  )
  update public.commands c
     set delivered_at = now(), status = 'executing'
    from claimed
   where c.id = claimed.id
  returning c.*;
end;
$$;

create or replace function public.complete_device_command(
  p_device_id uuid,
  p_command_id uuid,
  p_status text,
  p_result jsonb default null,
  p_error text default null
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_command public.commands%rowtype;
  v_action public.case_actions%rowtype;
  v_has_action boolean := false;
begin
  if p_status not in ('success','failed') then
    raise exception 'invalid terminal command status';
  end if;

  if not exists (
    select 1 from public.devices d
    where d.id = p_device_id
      and d.status = 'active'
      and d.cert_fingerprint is not null
  ) then
    raise exception 'device not authorized';
  end if;

  select * into v_command
    from public.commands
   where id = p_command_id
     and device_id = p_device_id
   for update;

  if not found then
    raise exception 'command not found for device';
  end if;

  if v_command.expires_at <= now() and v_command.status in ('pending','executing') then
    update public.commands
       set status='failed', executed_at=now(), error='command expired'
     where id=p_command_id;
    return jsonb_build_object('accepted',false,'status','failed','reason','expired');
  end if;

  if v_command.status not in ('executing','pending') then
    return jsonb_build_object('accepted',false,'status',v_command.status,'reason','terminal');
  end if;

  if v_command.status = 'pending' then
    return jsonb_build_object('accepted',false,'status','pending','reason','not_claimed');
  end if;

  update public.commands
     set status = p_status,
         executed_at = now(),
         result = p_result,
         error = case when p_status = 'failed'
                      then left(coalesce(p_error,'command failed'),1000)
                      else null end
   where id = p_command_id;

  select * into v_action
    from public.case_actions
   where command_id = p_command_id
   limit 1
   for update;

  v_has_action := found;

  if v_has_action then
    update public.case_actions
       set status = p_status,
           executed_at = now(),
           result = p_result,
           error = case when p_status = 'failed'
                        then left(coalesce(p_error,'command failed'),1000)
                        else null end
     where id = v_action.id;

    insert into public.case_timeline(case_id,actor,kind,payload)
    values (
      v_action.case_id,
      'agent:' || p_device_id::text,
      'response_command_result',
      jsonb_build_object(
        'case_action_id', v_action.id,
        'command_id', p_command_id,
        'status', p_status,
        'result', coalesce(p_result,'{}'::jsonb),
        'error', case when p_status = 'failed'
                      then left(coalesce(p_error,'command failed'),1000)
                      else null end
      )
    );
  end if;

  return jsonb_build_object(
    'accepted',true,
    'command_id',p_command_id,
    'status',p_status,
    'case_action_id',case when v_has_action then v_action.id else null end
  );
end;
$$;

revoke all on function public.claim_device_commands(uuid,integer) from public, anon, authenticated;
grant execute on function public.claim_device_commands(uuid,integer) to service_role;
revoke all on function public.complete_device_command(uuid,uuid,text,jsonb,text) from public, anon, authenticated;
grant execute on function public.complete_device_command(uuid,uuid,text,jsonb,text) to service_role;
