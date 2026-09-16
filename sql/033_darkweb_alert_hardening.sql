-- Sentinel Dark Web Monitoring: atomic alert/detection ingestion and case bridge.
-- Findings and alerts are tenant-bound and must not create duplicate detections.

create unique index if not exists dw_alerts_watch_finding_unique
    on public.dw_alerts(watchlist_id, finding_id);

create or replace function public.record_dw_finding(
    p_source_id text,
    p_content_hash text,
    p_kind text,
    p_matched_value text,
    p_context text,
    p_severity text,
    p_source_url text,
    p_metadata jsonb,
    p_tenant_id uuid,
    p_watchlist_id uuid
) returns table(finding_id bigint, alert_id uuid, detection_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_finding bigint;
    v_alert uuid;
    v_detection uuid;
    v_watch_tenant uuid;
    v_score real;
    v_verdict text;
    v_title text;
    v_severity text;
    v_case_id uuid;
begin
    if p_source_id is null or length(trim(p_source_id)) = 0 then raise exception 'invalid source'; end if;
    if p_content_hash is null or p_content_hash !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid content hash'; end if;
    if p_kind not in ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id') then raise exception 'invalid finding kind'; end if;
    if p_severity not in ('medium','high','critical') then raise exception 'invalid finding severity'; end if;

    if p_watchlist_id is not null then
        select tenant_id into v_watch_tenant from public.dw_watchlist where id = p_watchlist_id;
        if v_watch_tenant is null or p_tenant_id is null or v_watch_tenant <> p_tenant_id then
            raise exception 'watchlist tenant mismatch';
        end if;
    elsif p_tenant_id is not null then
        raise exception 'matched finding requires watchlist';
    end if;

    insert into public.dw_findings(source_id, content_hash, kind, matched_value, context, source_url, source_metadata, severity, tenant_id, watchlist_id)
    values (p_source_id, lower(p_content_hash), p_kind, left(p_matched_value,512), left(p_context,2000), left(p_source_url,2048), coalesce(p_metadata,'{}'::jsonb), p_severity, p_tenant_id, p_watchlist_id)
    on conflict (source_id, content_hash) do update
      set tenant_id = coalesce(excluded.tenant_id, public.dw_findings.tenant_id),
          watchlist_id = coalesce(excluded.watchlist_id, public.dw_findings.watchlist_id)
    returning id into v_finding;

    if p_tenant_id is not null and p_watchlist_id is not null then
        v_severity := p_severity;
        v_title := case p_kind
            when 'email' then 'Credential exposure detected'
            when 'domain' then 'Domain exposure detected'
            when 'wallet' then 'Wallet exposure detected'
            else 'Monitored data exposure detected'
        end;

        insert into public.dw_alerts(tenant_id, watchlist_id, finding_id, kind, severity, title, summary)
        values (p_tenant_id, p_watchlist_id, v_finding, p_kind, v_severity, v_title,
                left(coalesce(p_context,'Monitored identifier observed in an external source.'),2000))
        on conflict (watchlist_id, finding_id) do update
            set severity = greatest(public.dw_alerts.severity, excluded.severity),
                summary = coalesce(excluded.summary, public.dw_alerts.summary)
        returning id into v_alert;

        v_score := case v_severity when 'critical' then 0.99 when 'high' then 0.90 else 0.75 end;
        v_verdict := case when v_severity = 'critical' then 'malicious' else 'suspicious' end;

        insert into public.detections(tenant_id, device_id, event_id, detector, score, verdict, reasons, evidence, mitre_technique, processed_by_playbooks, processed_by_autocase)
        values (p_tenant_id, null, null, 'darkweb', v_score, v_verdict,
                array['external_exposure','darkweb_watchlist_match'],
                jsonb_build_object('alert_id',v_alert,'finding_id',v_finding,'source_id',p_source_id,'kind',p_kind),
                'T1589', false, false)
        on conflict do nothing
        returning id into v_detection;

        if v_detection is not null then
            begin
                select public.create_case_from_detection(v_detection) into v_case_id;
                if v_case_id is not null then
                    update public.dw_alerts set case_id = v_case_id, status = 'investigating' where id = v_alert;
                end if;
            exception when others then
                -- Detection remains durable; case creation can be retried by the response layer.
                null;
            end;
        end if;
    end if;

    return query select v_finding, v_alert, v_detection;
end;
$$;

revoke all on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) from public, anon, authenticated;
grant execute on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) to service_role;
