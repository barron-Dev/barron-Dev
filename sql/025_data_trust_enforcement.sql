-- Sentinel Data Trust enforcement bridge, migration 025.
-- Keeps policy decisions and downstream detection creation atomic.
-- Endpoint agents remain responsible for the actual OS-level block/quarantine action.

alter table public.data_trust_transfer_events
    add column if not exists idempotency_key text,
    add column if not exists detection_id uuid references public.detections(id) on delete set null,
    add column if not exists enforcement_status text not null default 'decision_only'
        check (enforcement_status in ('decision_only','enforced','failed','not_required'));

create unique index if not exists data_trust_transfer_events_idempotency_idx
    on public.data_trust_transfer_events (tenant_id, idempotency_key)
    where idempotency_key is not null;

create index if not exists data_trust_transfer_events_detection_idx
    on public.data_trust_transfer_events (detection_id)
    where detection_id is not null;

create index if not exists data_trust_transfer_events_tenant_observed_idx
    on public.data_trust_transfer_events (tenant_id, observed_at desc);

create or replace function public.record_data_trust_transfer(
    p_tenant_id uuid,
    p_asset_id uuid,
    p_device_id uuid,
    p_actor_id uuid,
    p_source_type text,
    p_destination_type text,
    p_destination_ref text,
    p_destination_trust text,
    p_bytes_transferred bigint,
    p_content_inspected boolean,
    p_content_hash text,
    p_observed_at timestamptz,
    p_metadata jsonb,
    p_decision text,
    p_reason_codes text[],
    p_policy_id uuid,
    p_classification text,
    p_idempotency_key text
)
returns table(event_id uuid, detection_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_event_id uuid;
    v_detection_id uuid;
    v_score real;
    v_verdict text;
    v_device_tenant uuid;
    v_asset_tenant uuid;
begin
    if p_tenant_id is null then
        raise exception 'tenant_id is required';
    end if;

    if p_decision not in ('allow','block','quarantine','review') then
        raise exception 'invalid transfer decision';
    end if;

    if p_idempotency_key is null or length(trim(p_idempotency_key)) < 16 or length(p_idempotency_key) > 256 then
        raise exception 'invalid idempotency_key';
    end if;

    if p_asset_id is not null then
        select tenant_id into v_asset_tenant
        from public.data_trust_assets
        where id = p_asset_id;
        if v_asset_tenant is null or v_asset_tenant <> p_tenant_id then
            raise exception 'asset is not owned by tenant';
        end if;
    end if;

    if p_device_id is not null then
        select tenant_id into v_device_tenant
        from public.devices
        where id = p_device_id;
        if v_device_tenant is null or v_device_tenant <> p_tenant_id then
            raise exception 'device is not owned by tenant';
        end if;
    end if;

    select id, detection_id into v_event_id, v_detection_id
    from public.data_trust_transfer_events
    where tenant_id = p_tenant_id and idempotency_key = p_idempotency_key;

    if v_event_id is not null then
        return query select v_event_id, v_detection_id;
        return;
    end if;

    insert into public.data_trust_transfer_events (
        tenant_id, asset_id, device_id, actor_id, source_type,
        destination_type, destination_ref, destination_trust,
        bytes_transferred, content_inspected, content_hash,
        decision, reason_codes, observed_at, metadata,
        idempotency_key, enforcement_status
    ) values (
        p_tenant_id, p_asset_id, p_device_id, p_actor_id, p_source_type,
        p_destination_type, p_destination_ref, p_destination_trust,
        p_bytes_transferred, p_content_inspected, p_content_hash,
        p_decision, coalesce(p_reason_codes, '{}'::text[]), p_observed_at,
        coalesce(p_metadata, '{}'::jsonb), p_idempotency_key,
        case when p_decision = 'allow' then 'not_required' else 'decision_only' end
    ) returning id into v_event_id;

    if p_decision in ('block','quarantine') then
        v_score := case
            when p_classification in ('regulated','restricted') then 0.99
            when p_classification = 'confidential' then 0.90
            when p_classification = 'internal' then 0.75
            else 0.65
        end;
        v_verdict := case when p_decision = 'quarantine' then 'quarantine' else 'block' end;

        insert into public.detections (
            tenant_id, device_id, event_id, detector, score, verdict,
            reasons, evidence, mitre_technique, processed_by_playbooks,
            processed_by_autocase
        ) values (
            p_tenant_id, p_device_id, v_event_id, 'data_trust', v_score,
            v_verdict, coalesce(p_reason_codes, '{}'::text[]),
            jsonb_build_object(
                'transfer_event_id', v_event_id,
                'asset_id', p_asset_id,
                'destination_type', p_destination_type,
                'destination_trust', p_destination_trust,
                'bytes_transferred', p_bytes_transferred,
                'classification', p_classification,
                'policy_id', p_policy_id
            ),
            'T1041', false, false
        ) returning id into v_detection_id;

        update public.data_trust_transfer_events
        set detection_id = v_detection_id
        where id = v_event_id;
    end if;

    return query select v_event_id, v_detection_id;
end;
$$;

revoke all on function public.record_data_trust_transfer(
    uuid, uuid, uuid, uuid, text, text, text, text, bigint, boolean,
    text, timestamptz, jsonb, text, text[], uuid, text, text
) from public, anon, authenticated;
grant execute on function public.record_data_trust_transfer(
    uuid, uuid, uuid, uuid, text, text, text, text, bigint, boolean,
    text, timestamptz, jsonb, text, text[], uuid, text, text
) to service_role;
