-- Sentinel Deception -> Detection -> AutoCase bridge, migration 020.
-- A trigger is promoted only when the deception artifact is explicitly bound to
-- an endpoint device and an existing tenant-owned auto-case rule.

alter table deception_artifacts
    add column if not exists device_id uuid references devices(id) on delete set null,
    add column if not exists auto_case_rule_id uuid references auto_case_rules(id) on delete set null;

create index if not exists idx_deception_artifacts_device
    on deception_artifacts(device_id) where device_id is not null;

create index if not exists idx_deception_artifacts_rule
    on deception_artifacts(auto_case_rule_id) where auto_case_rule_id is not null;

-- Existing authenticated tenants may read their own bindings; writes remain
-- through the existing provisioning service/API path.
create policy deception_artifacts_tenant_update on deception_artifacts
    for update to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid))
    with check (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

grant update on deception_artifacts to authenticated;

create or replace function deception_finalize_trigger(p_trigger_id uuid)
returns table (trigger_id uuid, detection_id uuid, case_id uuid, case_status text)
language plpgsql
security definer
set search_path = public
as $$
declare
    t deception_triggers%rowtype;
    a deception_artifacts%rowtype;
    d_id uuid;
    c_id uuid;
    v_case_status text := 'pending';
    v_rule_category text;
    v_rule_severity text;
    v_title text;
    v_summary text;
    v_device_id uuid;
    v_evidence jsonb;
    v_actor text := 'deception:callback';
begin
    if p_trigger_id is null then
        raise exception 'trigger id is required';
    end if;

    select * into t
      from deception_triggers
     where id = p_trigger_id
     for update;

    if not found then
        raise exception 'deception trigger not found';
    end if;

    if t.case_status in ('created', 'suppressed') then
        return query select t.id, null::uuid, t.case_id, t.case_status;
        return;
    end if;

    select * into a
      from deception_artifacts
     where id = t.artifact_id
       and tenant_id = t.tenant_id
     for update;

    if not found then
        update deception_triggers set case_status = 'failed' where id = t.id;
        return query select t.id, null::uuid, null::uuid, 'failed'::text;
        return;
    end if;

    v_device_id := a.device_id;
    if v_device_id is null then
        update deception_triggers
           set case_status = 'failed',
               evidence = evidence || jsonb_build_object('autocase', 'device_binding_required')
         where id = t.id;
        return query select t.id, null::uuid, null::uuid, 'failed'::text;
        return;
    end if;

    if not exists (select 1 from devices where id = v_device_id and tenant_id = t.tenant_id) then
        update deception_triggers
           set case_status = 'failed',
               evidence = evidence || jsonb_build_object('autocase', 'device_tenant_mismatch')
         where id = t.id;
        return query select t.id, null::uuid, null::uuid, 'failed'::text;
        return;
    end if;

    if a.auto_case_rule_id is null then
        update deception_triggers
           set case_status = 'failed',
               evidence = evidence || jsonb_build_object('autocase', 'rule_binding_required')
         where id = t.id;
        return query select t.id, null::uuid, null::uuid, 'failed'::text;
        return;
    end if;

    select category, severity, name
      into v_rule_category, v_rule_severity, v_title
      from auto_case_rules
     where id = a.auto_case_rule_id
       and tenant_id = t.tenant_id
       and enabled = true;

    if not found then
        update deception_triggers
           set case_status = 'failed',
               evidence = evidence || jsonb_build_object('autocase', 'rule_missing_disabled_or_cross_tenant')
         where id = t.id;
        return query select t.id, null::uuid, null::uuid, 'failed'::text;
        return;
    end if;

    v_title := 'Deception trigger: ' || left(a.name, 180);
    v_summary := format('A %s deception artifact was accessed or contacted.', a.artifact_type);
    v_evidence := coalesce(t.evidence, '{}'::jsonb)
        || jsonb_build_object(
            'deception_trigger_id', t.id,
            'deception_artifact_id', a.id,
            'artifact_type', a.artifact_type,
            'artifact_name', a.name,
            'source_ip', t.source_ip,
            'source_country', t.source_country,
            'source_asn', t.source_asn,
            'source_org', t.source_org,
            'observed_at', t.observed_at
        );

    insert into detections (
        tenant_id, device_id, detector, score, verdict, reasons, evidence, created_at
    ) values (
        t.tenant_id,
        v_device_id,
        'deception',
        case when t.alert_severity = 'critical' then 1.0 else 0.95 end,
        'malicious',
        array['deception_artifact_triggered', a.artifact_type],
        v_evidence,
        t.observed_at
    ) returning id into d_id;

    c_id := create_case_from_detection(
        t.tenant_id,
        a.auto_case_rule_id,
        d_id,
        v_rule_category,
        case when t.alert_severity = 'critical' then 'critical' else greatest(v_rule_severity, 'high') end,
        v_title,
        v_summary,
        v_evidence,
        v_device_id,
        v_actor
    );

    update deception_triggers
       set case_status = 'created', case_id = c_id
     where id = t.id;

    update detections
       set processed_by_autocase = true
     where id = d_id;

    return query select t.id, d_id, c_id, 'created'::text;
exception when others then
    update deception_triggers
       set case_status = 'failed',
           evidence = coalesce(evidence, '{}'::jsonb) || jsonb_build_object('autocase_error', sqlerrm)
     where id = p_trigger_id;
    return query select p_trigger_id, null::uuid, null::uuid, 'failed'::text;
end;
$$;

revoke all on function deception_finalize_trigger(uuid) from public, anon, authenticated;
grant execute on function deception_finalize_trigger(uuid) to service_role;
