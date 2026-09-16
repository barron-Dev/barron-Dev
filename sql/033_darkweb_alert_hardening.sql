-- Sentinel Dark Web Monitoring: atomic alert/detection ingestion.
-- Findings and alerts are tenant-bound and detection creation is idempotent.
-- Case creation remains owned by the existing AutoCase engine/rules.

create unique index if not exists detections_darkweb_finding_unique
    on public.detections (tenant_id, detector, ((evidence ->> 'finding_id')))
    where detector = 'darkweb' and evidence ? 'finding_id';

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
begin
    if p_source_id is null or length(trim(p_source_id)) = 0 then
        raise exception 'invalid source';
    end if;
    if p_content_hash is null or p_content_hash !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid content hash';
    end if;
    if p_kind not in ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id') then
        raise exception 'invalid finding kind';
    end if;
    if p_severity not in ('medium','high','critical') then
        raise exception 'invalid finding severity';
    end if;
    if p_matched_value is null or length(trim(p_matched_value)) = 0 then
        raise exception 'matched value is required';
    end if;

    if p_watchlist_id is not null then
        select tenant_id into v_watch_tenant
        from public.dw_watchlist
        where id = p_watchlist_id;

        if v_watch_tenant is null or p_tenant_id is null or v_watch_tenant <> p_tenant_id then
            raise exception 'watchlist tenant mismatch';
        end if;
    elsif p_tenant_id is not null then
        raise exception 'matched finding requires watchlist';
    end if;

    insert into public.dw_findings(
        source_id, content_hash, kind, matched_value, context,
        source_url, source_metadata, severity, tenant_id, watchlist_id
    )
    values (
        p_source_id, lower(p_content_hash), p_kind, left(p_matched_value,512),
        left(p_context,2000), left(p_source_url,2048), coalesce(p_metadata,'{}'::jsonb),
        p_severity, p_tenant_id, p_watchlist_id
    )
    on conflict (source_id, content_hash) do update
      set tenant_id = coalesce(excluded.tenant_id, public.dw_findings.tenant_id),
          watchlist_id = coalesce(excluded.watchlist_id, public.dw_findings.watchlist_id),
          severity = case
              when public.dw_findings.severity = 'critical' or excluded.severity = 'critical' then 'critical'
              when public.dw_findings.severity = 'high' or excluded.severity = 'high' then 'high'
              else 'medium'
          end
    returning id into v_finding;

    if p_tenant_id is not null and p_watchlist_id is not null then
        select case
            when w.severity = 'critical' or p_severity = 'critical' then 'critical'
            when w.severity = 'high' or p_severity = 'high' then 'high'
            else 'medium'
        end
        into v_severity
        from public.dw_watchlist w
        where w.id = p_watchlist_id
          and w.tenant_id = p_tenant_id;

        if v_severity is null then
            raise exception 'watchlist disappeared during ingestion';
        end if;

        v_title := case p_kind
            when 'email' then 'Credential exposure detected'
            when 'domain' then 'Domain exposure detected'
            when 'wallet' then 'Wallet exposure detected'
            else 'Monitored data exposure detected'
        end;

        insert into public.dw_alerts(
            tenant_id, watchlist_id, finding_id, kind, severity, title, summary
        )
        values (
            p_tenant_id, p_watchlist_id, v_finding, p_kind, v_severity, v_title,
            left(coalesce(p_context,'Monitored identifier observed in an external source.'),2000)
        )
        on conflict (watchlist_id, finding_id) do update
            set severity = case
                when public.dw_alerts.severity = 'critical' or excluded.severity = 'critical' then 'critical'
                when public.dw_alerts.severity = 'high' or excluded.severity = 'high' then 'high'
                else 'medium'
            end,
            summary = coalesce(excluded.summary, public.dw_alerts.summary)
        returning id into v_alert;

        v_score := case v_severity
            when 'critical' then 0.99
            when 'high' then 0.90
            else 0.75
        end;
        v_verdict := case when v_severity = 'critical' then 'malicious' else 'suspicious' end;

        -- Detection is the durable bridge into the existing Detection ->
        -- Playbook/AutoCase pipeline. We deliberately do not create a case here:
        -- AutoCase rules remain the policy boundary for automatic case creation.
        insert into public.detections(
            tenant_id, device_id, event_id, detector, score, verdict, reasons,
            evidence, mitre_technique, processed_by_playbooks, processed_by_autocase
        )
        values (
            p_tenant_id, null, null, 'darkweb', v_score, v_verdict,
            array['external_exposure','darkweb_watchlist_match'],
            jsonb_build_object(
                'alert_id', v_alert,
                'finding_id', v_finding,
                'source_id', p_source_id,
                'kind', p_kind
            ),
            null, false, false
        )
        on conflict (tenant_id, detector, ((evidence ->> 'finding_id')))
            where detector = 'darkweb' and evidence ? 'finding_id'
        do update set
            score = greatest(public.detections.score, excluded.score),
            verdict = case
                when public.detections.verdict = 'malicious' or excluded.verdict = 'malicious' then 'malicious'
                else 'suspicious'
            end,
            evidence = public.detections.evidence || excluded.evidence
        returning id into v_detection;
    end if;

    return query select v_finding, v_alert, v_detection;
end;
$$;

revoke all on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) from public, anon, authenticated;
grant execute on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) to service_role;
