-- Sentinel Investigation start claim, migration 024.
-- Atomically reserves a requested session for one approval attempt.
create or replace function public.claim_investigation_start(
    p_session_id uuid,
    p_tenant_id uuid
)
returns table (
    id uuid,
    tenant_id uuid,
    case_id uuid,
    created_by uuid,
    purpose text,
    authorization_ref text,
    status text,
    provider text,
    provider_session_id text,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz,
    updated_at timestamptz
)
language sql
security definer
set search_path = public
as $$
    update investigation_sessions
       set status = 'approved',
           updated_at = now()
     where investigation_sessions.id = p_session_id
       and investigation_sessions.tenant_id = p_tenant_id
       and investigation_sessions.status = 'requested'
    returning investigation_sessions.*;
$$;

revoke all on function public.claim_investigation_start(uuid, uuid) from public, anon, authenticated;
grant execute on function public.claim_investigation_start(uuid, uuid) to service_role;
