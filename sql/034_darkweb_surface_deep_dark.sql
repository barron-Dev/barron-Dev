-- Sentinel Exposure Intelligence: explicit surface/deep/dark provenance.
-- A source's web layer is descriptive; access_mode records how Sentinel obtained it.
-- Sentinel only collects public material or data for which the customer has
-- authorized access. It does not bypass authentication, paywalls, or access controls.

alter table public.dw_sources
    add column if not exists web_layer text not null default 'surface'
        check (web_layer in ('surface','deep','dark','breach_intel')),
    add column if not exists access_mode text not null default 'public'
        check (access_mode in ('public','authenticated_customer','licensed_feed','customer_connector'));

alter table public.dw_findings
    add column if not exists web_layer text not null default 'surface'
        check (web_layer in ('surface','deep','dark','breach_intel')),
    add column if not exists access_mode text not null default 'public'
        check (access_mode in ('public','authenticated_customer','licensed_feed','customer_connector')),
    add column if not exists collected_at timestamptz not null default now();

create index if not exists dw_findings_layer_idx
    on public.dw_findings(tenant_id, web_layer, collected_at desc);

create index if not exists dw_sources_layer_idx
    on public.dw_sources(web_layer, enabled);

-- Global source registry: clients never write source configuration directly.
alter table public.dw_sources enable row level security;

-- Classify the sources Sentinel already supports. Public Telegram/Paste/GitHub are
-- surface-web collection, while breach/ransomware intelligence is a separate class.
update public.dw_sources
   set web_layer = 'breach_intel', access_mode = 'licensed_feed'
 where id = 'hibp';
update public.dw_sources
   set web_layer = 'dark', access_mode = 'public'
 where id = 'ransomwatch';
update public.dw_sources
   set web_layer = 'surface', access_mode = 'public'
 where id in ('pastebin_public','telegram_public','github_code');

-- Source provenance is authoritative at ingestion time. Do not trust a caller to
-- label a source as dark/deep/surface.
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
    v_source_layer text;
    v_source_access text;
    v_existing_score real;
    v_score real;
    v_verdict text;
    v_title text;
    v_severity text;
    v_existing_verdict text;
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

    select web_layer, access_mode
      into v_source_layer, v_source_access
      from public.dw_sources
     where id = p_source_id and enabled = true;
    if v_source_layer is null then
        raise exception 'source is not registered or enabled';
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
        source_url, source_metadata, severity, tenant_id, watchlist_id,
        web_layer, access_mode, collected_at
    )
    values (
        p_source_id, lower(p_content_hash), p_kind, left(p_matched_value,512),
        left(p_context,2000), left(p_source_url,2048), coalesce(p_metadata,'{}'::jsonb),
        p_severity, p_tenant_id, p_watchlist_id, v_source_layer, v_source_access, now()
    )
    on conflict (source_id, content_hash) do update
      set tenant_id = coalesce(excluded.tenant_id, public.dw_findings.tenant_id),
          watchlist_id = coalesce(excluded.watchlist_id, public.dw_findings.watchlist_id),
          severity = case
              when public.dw_findings.severity = 'critical' or excluded.severity = 'critical' then 'critical'
              when public.dw_findings.severity = 'high' or excluded.severity = 'high' then 'high'
              else 'medium'
          end,
          web_layer = excluded.web_layer,
          access_mode = excluded.access_mode,
          collected_at = excluded.collected_at
    returning id into v_finding;

    if p_tenant_id is not null and p_watchlist_id is not null then
        select case
            when w.severity = 'critical' or p_severity = 'critical' then 'critical'
            when w.severity = 'high' or p_severity = 'high' then 'high'
            else 'medium'
        end
        into v_severity
        from public.dw_watchlist w
        where w.id = p_watchlist_id and w.tenant_id = p_tenant_id;
        if v_severity is null then
            raise exception 'watchlist disappeared during ingestion';
        end if;

        v_title := case
            when v_source_layer = 'dark' then 'Dark-web exposure detected'
            when v_source_layer = 'breach_intel' then 'Breach exposure detected'
            when v_source_layer = 'deep' then 'Deep-web exposure detected'
            when p_kind = 'email' then 'Credential exposure detected'
            else 'Monitored data exposure detected'
        end;

        insert into public.dw_alerts(tenant_id, watchlist_id, finding_id, kind, severity, title, summary)
        values (p_tenant_id, p_watchlist_id, v_finding, p_kind, v_severity, v_title,
                left(coalesce(p_context,'Monitored identifier observed in an external source.'),2000))
        on conflict (watchlist_id, finding_id) do update
          set severity = case
              when public.dw_alerts.severity = 'critical' or excluded.severity = 'critical' then 'critical'
              when public.dw_alerts.severity = 'high' or excluded.severity = 'high' then 'high'
              else 'medium'
          end,
          summary = coalesce(excluded.summary, public.dw_alerts.summary)
        returning id into v_alert;

        v_score := case v_severity when 'critical' then 0.99 when 'high' then 0.90 else 0.75 end;
        v_verdict := case when v_severity = 'critical' then 'malicious' else 'suspicious' end;

        perform pg_advisory_xact_lock(
            hashtextextended(format('%s:%s', p_tenant_id::text, v_finding::text), 0)
        );

        select d.id, d.score, d.verdict
          into v_detection, v_existing_score, v_existing_verdict
          from public.detections d
         where d.tenant_id = p_tenant_id
           and d.detector = 'darkweb'
           and d.evidence ->> 'finding_id' = v_finding::text
         order by d.created_at
         limit 1
         for update;

        if v_detection is null then
            insert into public.detections(
                tenant_id, device_id, event_id, detector, score, verdict, reasons,
                evidence, mitre_technique, processed_by_playbooks, processed_by_autocase
            )
            values (
                p_tenant_id, null, null, 'darkweb', v_score, v_verdict,
                array['external_exposure','darkweb_watchlist_match'],
                jsonb_build_object('alert_id',v_alert,'finding_id',v_finding,'source_id',p_source_id,
                                   'kind',p_kind,'web_layer',v_source_layer,'access_mode',v_source_access),
                null, false, false
            )
            returning id into v_detection;
        else
            update public.detections
               set score = greatest(coalesce(v_existing_score,0), v_score),
                   verdict = case when v_existing_verdict = 'malicious' or v_verdict = 'malicious' then 'malicious' else 'suspicious' end,
                   evidence = evidence || jsonb_build_object('alert_id',v_alert,'source_id',p_source_id,
                                                             'web_layer',v_source_layer,'access_mode',v_source_access)
             where id = v_detection;
        end if;
    end if;

    return query select v_finding, v_alert, v_detection;
end;
$$;

revoke all on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) from public, anon, authenticated;
grant execute on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) to service_role;
