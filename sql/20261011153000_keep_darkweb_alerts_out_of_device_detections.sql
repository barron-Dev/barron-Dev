-- External dark-web exposure is not a device detection. Persist its finding and
-- alert, but do not fabricate a device_id or force it into the endpoint verdict enum.
do $migration$
declare
  v_definition text;
  v_updated text;
  v_old text;
begin
  v_definition := pg_get_functiondef(
    'public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid)'::regprocedure
  );
  v_old := $old$
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
$old$;
  if position(v_old in v_definition) = 0 then
    raise exception 'Expected legacy detection insertion block not found; refusing partial rewrite';
  end if;
  v_updated := replace(
    v_definition,
    v_old,
    E'        -- External exposure remains represented by dw_findings and dw_alerts.\n        -- detections requires a real device_id and endpoint verdict; do not fabricate either.\n        v_detection := null;\n'
  );
  execute v_updated;
end
$migration$;
