-- Cyclothone device PKI enrollment runtime.
-- Atomic token validation, device creation, and token consumption.

create or replace function public.enroll_device_atomic(
    p_token_hash text,
    p_name text,
    p_hostname text,
    p_os text,
    p_os_version text,
    p_arch text,
    p_platform text,
    p_platform_version text,
    p_agent_version text,
    p_public_key_pem text,
    p_certificate_pem text,
    p_certificate_serial text,
    p_certificate_not_before timestamptz,
    p_certificate_not_after timestamptz,
    p_cert_fingerprint text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_token public.device_enrollment_tokens%rowtype;
    v_device_id uuid;
begin
    if p_token_hash is null or p_token_hash !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid enrollment token';
    end if;

    if p_name is null or length(trim(p_name)) = 0 or length(p_name) > 255 then
        raise exception 'invalid device name';
    end if;

    if p_hostname is null or length(trim(p_hostname)) = 0 or length(p_hostname) > 255 then
        raise exception 'invalid hostname';
    end if;

    if p_cert_fingerprint is null or p_cert_fingerprint !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid certificate fingerprint';
    end if;

    if p_certificate_pem is null or p_certificate_serial is null
       or p_certificate_not_before is null or p_certificate_not_after is null then
        raise exception 'complete certificate identity is required';
    end if;

    select *
      into v_token
      from public.device_enrollment_tokens
     where token_hash = lower(p_token_hash)
       and used_at is null
       and expires_at > now()
     for update;

    if not found then
        raise exception 'enrollment token is invalid, expired, or already used';
    end if;

    insert into public.devices (
        tenant_id, hostname, os, os_version, arch, attestation,
        last_seen_at, status, name, platform, platform_version,
        agent_version, public_key, public_key_pem, certificate_pem,
        certificate_serial, certificate_not_before, certificate_not_after,
        cert_fingerprint, updated_at
    )
    values (
        v_token.tenant_id, trim(p_hostname), trim(p_os), p_os_version, p_arch, '{}'::jsonb,
        now(), 'active', trim(p_name), trim(p_platform), p_platform_version,
        p_agent_version, p_public_key_pem, p_public_key_pem, p_certificate_pem,
        p_certificate_serial, p_certificate_not_before, p_certificate_not_after,
        lower(p_cert_fingerprint), now()
    )
    returning id into v_device_id;

    update public.device_enrollment_tokens
       set used_at = now(), device_id = v_device_id
     where id = v_token.id;

    return jsonb_build_object(
        'device_id', v_device_id,
        'tenant_id', v_token.tenant_id,
        'token_id', v_token.id
    );
exception
    when unique_violation then
        raise exception 'device identity or hostname already exists';
end;
$$;

revoke all on function public.enroll_device_atomic(
    text,text,text,text,text,text,text,text,text,text,text,text,
    timestamptz,timestamptz,text
) from public, anon, authenticated;

grant execute on function public.enroll_device_atomic(
    text,text,text,text,text,text,text,text,text,text,text,text,
    timestamptz,timestamptz,text
) to service_role;


-- Reconcile the existing command runtime with the canonical device lifecycle.
create or replace function public.claim_device_commands(p_device_id uuid, p_limit integer default 10)
returns setof public.commands language plpgsql security definer set search_path = '' as $$
begin
  if p_limit < 1 or p_limit > 50 then raise exception 'invalid command batch size'; end if;
  if not exists (select 1 from public.devices d where d.id=p_device_id and d.status='active' and d.cert_fingerprint is not null) then
    raise exception 'device not authorized';
  end if;
  return query
  with claimed as (
    select c.id from public.commands c
    where c.device_id=p_device_id and c.status='pending' and c.delivered_at is null and c.expires_at>now()
    order by c.issued_at for update skip locked limit p_limit
  )
  update public.commands c set delivered_at=now(),status='executing'
  from claimed where c.id=claimed.id returning c.*;
end; $$;
revoke all on function public.claim_device_commands(uuid,integer) from public,anon,authenticated;
grant execute on function public.claim_device_commands(uuid,integer) to service_role;

create or replace function public.complete_device_command(p_device_id uuid,p_command_id uuid,p_status text,p_result jsonb default null,p_error text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_command public.commands%rowtype; v_action public.case_actions%rowtype; v_has_action boolean:=false;
begin
  if p_status not in ('success','failed') then raise exception 'invalid terminal command status'; end if;
  if not exists (select 1 from public.devices d where d.id=p_device_id and d.status='active' and d.cert_fingerprint is not null) then raise exception 'device not authorized'; end if;
  select * into v_command from public.commands where id=p_command_id and device_id=p_device_id for update;
  if not found then raise exception 'command not found for device'; end if;
  if v_command.status not in ('executing','pending') then return jsonb_build_object('accepted',false,'status',v_command.status); end if;
  update public.commands set status=p_status,executed_at=now(),result=p_result,error=case when p_status='failed' then left(coalesce(p_error,'command failed'),1000) else null end where id=p_command_id;
  select * into v_action from public.case_actions where command_id=p_command_id limit 1 for update;
  v_has_action:=found;
  if v_has_action then
    update public.case_actions set status=p_status,executed_at=now(),result=p_result,error=case when p_status='failed' then left(coalesce(p_error,'command failed'),1000) else null end where id=v_action.id;
    insert into public.case_timeline(case_id,actor,kind,payload) values(v_action.case_id,'agent:'||p_device_id::text,'response_command_result',jsonb_build_object('case_action_id',v_action.id,'command_id',p_command_id,'status',p_status,'result',coalesce(p_result,'{}'::jsonb),'error',case when p_status='failed' then left(coalesce(p_error,'command failed'),1000) else null end));
  end if;
  return jsonb_build_object('accepted',true,'command_id',p_command_id,'status',p_status,'case_action_id',case when v_has_action then v_action.id else null end);
end; $$;
revoke all on function public.complete_device_command(uuid,uuid,text,jsonb,text) from public,anon,authenticated;
grant execute on function public.complete_device_command(uuid,uuid,text,jsonb,text) to service_role;
