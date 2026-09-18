-- Create tenant-scoped, one-time device enrollment tokens through the authenticated control plane.
create or replace function public.create_device_enrollment_token(
    p_app_id uuid,
    p_token_hash text,
    p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_app public.developer_apps%rowtype;
    v_token_id uuid;
begin
    if p_token_hash is null or p_token_hash !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid enrollment token hash';
    end if;

    if p_expires_at is null or p_expires_at <= now() or p_expires_at > now() + interval '24 hours' then
        raise exception 'invalid enrollment token expiry';
    end if;

    select *
      into v_app
      from public.developer_apps
     where id = p_app_id
       and active = true
     for share;

    if not found then
        raise exception 'application is not active';
    end if;

    insert into public.device_enrollment_tokens (
        tenant_id, created_by, token_hash, expires_at
    )
    values (
        v_app.tenant_id, v_app.owner_user_id, lower(p_token_hash), p_expires_at
    )
    returning id into v_token_id;

    return jsonb_build_object(
        'token_id', v_token_id,
        'tenant_id', v_app.tenant_id,
        'expires_at', p_expires_at
    );
end;
$$;

revoke all on function public.create_device_enrollment_token(uuid,text,timestamptz)
from public, anon, authenticated;

grant execute on function public.create_device_enrollment_token(uuid,text,timestamptz)
to service_role;
