-- Sentinel Data Trust enforcement acknowledgement, migration 026.
-- The control plane decides; a trusted endpoint adapter reports whether the OS
-- enforcement action actually succeeded.

create or replace function public.report_data_trust_enforcement(
    p_tenant_id uuid,
    p_event_id uuid,
    p_status text,
    p_metadata jsonb
)
returns public.data_trust_transfer_events
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_event public.data_trust_transfer_events;
begin
    if p_status not in ('enforced','failed') then
        raise exception 'invalid enforcement status';
    end if;

    update public.data_trust_transfer_events
    set enforcement_status = p_status,
        metadata = metadata || coalesce(p_metadata, '{}'::jsonb)
    where id = p_event_id
      and tenant_id = p_tenant_id
      and decision in ('block','quarantine')
    returning * into v_event;

    if v_event.id is null then
        raise exception 'transfer event not found or not enforceable';
    end if;

    return v_event;
end;
$$;

revoke all on function public.report_data_trust_enforcement(uuid,uuid,text,jsonb) from public, anon, authenticated;
grant execute on function public.report_data_trust_enforcement(uuid,uuid,text,jsonb) to service_role;
