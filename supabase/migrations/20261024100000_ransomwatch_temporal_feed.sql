-- Ransomwatch temporal-feed correction.
-- Safe to apply after 20261022110000_dw_trust_boundary_foundation.sql.
-- This does not promote old records or claim direct onion access.
BEGIN;

UPDATE public.dw_sources
   SET enabled = true,
       web_layer = 'surface',
       access_mode = 'public_feed',
       poll_interval_seconds = 1800,
       last_status = 'awaiting_runtime_poll'
 WHERE id = 'ransomwatch';

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='dw_sources' AND column_name='source_class'
  ) THEN
    ALTER TABLE public.dw_sources DROP CONSTRAINT IF EXISTS dw_sources_source_class_check;
    ALTER TABLE public.dw_sources ADD CONSTRAINT dw_sources_source_class_check
      CHECK (source_class IN (
        'native_onion','telegram_public','pastebin_public','bluesky_public',
        'github_code_search','tiktok_commercial','ransomwatch_feed',
        'historical_archive','excluded','unclassified'
      ));
    UPDATE public.dw_sources SET source_class='ransomwatch_feed' WHERE id='ransomwatch';
  END IF;

  IF to_regclass('public.dw_source_type_requirements') IS NOT NULL THEN
    ALTER TABLE public.dw_source_type_requirements
      DROP CONSTRAINT IF EXISTS dw_source_type_requirements_source_class_check;
    ALTER TABLE public.dw_source_type_requirements
      ADD CONSTRAINT dw_source_type_requirements_source_class_check
      CHECK (source_class IN (
        'native_onion','telegram_public','pastebin_public','bluesky_public',
        'github_code_search','tiktok_commercial','ransomwatch_feed',
        'historical_archive','excluded','unclassified'
      ));
    INSERT INTO public.dw_source_type_requirements (
      source_class, requires_route_verified, requires_hs_desc_content,
      requires_descriptor_fetch, requires_rendezvous_hop,
      requires_stream_circuit_binding, requires_auth, max_age_seconds
    ) VALUES ('ransomwatch_feed', false, false, false, false, false, false, 3600)
    ON CONFLICT (source_class) DO UPDATE SET
      requires_route_verified=false,
      requires_hs_desc_content=false,
      requires_descriptor_fetch=false,
      requires_rendezvous_hop=false,
      requires_stream_circuit_binding=false,
      requires_auth=false,
      max_age_seconds=3600;
  END IF;
END $$;

-- Refresh source metadata/class on a duplicate hash. Otherwise a finding first
-- observed as old data can remain archived forever after the live feed updates.
CREATE OR REPLACE FUNCTION public.record_dw_finding(
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
)
RETURNS TABLE(finding_id bigint, alert_id uuid, detection_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_finding bigint;
    v_alert uuid;
    v_detection uuid;
    v_watch_tenant uuid;
    v_source_layer text;
    v_source_access text;
    v_verdict text;
    v_title text;
    v_severity text;
    v_finding_class text;
BEGIN
    IF p_source_id IS NULL OR length(trim(p_source_id)) = 0 THEN
        RAISE EXCEPTION 'invalid source';
    END IF;
    IF p_content_hash IS NULL OR p_content_hash !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'invalid content hash';
    END IF;
    IF p_kind NOT IN ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id') THEN
        RAISE EXCEPTION 'invalid finding kind';
    END IF;
    IF p_severity NOT IN ('medium','high','critical') THEN
        RAISE EXCEPTION 'invalid finding severity';
    END IF;
    IF p_matched_value IS NULL OR length(trim(p_matched_value)) = 0 THEN
        RAISE EXCEPTION 'matched value is required';
    END IF;

    SELECT web_layer, access_mode
      INTO v_source_layer, v_source_access
      FROM public.dw_sources
     WHERE id = p_source_id AND enabled = true;
    IF v_source_layer IS NULL THEN
        RAISE EXCEPTION 'source is not registered or enabled';
    END IF;

    IF p_watchlist_id IS NOT NULL THEN
        SELECT tenant_id INTO v_watch_tenant
          FROM public.dw_watchlist
         WHERE id = p_watchlist_id;
        IF v_watch_tenant IS NULL OR p_tenant_id IS NULL OR v_watch_tenant <> p_tenant_id THEN
            RAISE EXCEPTION 'watchlist tenant mismatch';
        END IF;
    ELSIF p_tenant_id IS NOT NULL THEN
        RAISE EXCEPTION 'matched finding requires watchlist';
    END IF;

    v_finding_class := CASE
      WHEN p_source_id = 'ransomwatch'
       AND coalesce(p_metadata->>'temporal_class','') = 'current_feed' THEN 'surface_public'
      WHEN p_source_id IN ('telegram_public','pastebin_public','bluesky_public','github_code','tiktok_commercial') THEN 'surface_public'
      WHEN p_source_id = 'ransomwatch' THEN 'historical_archive'
      ELSE 'historical_archive'
    END;

    INSERT INTO public.dw_findings(
        source_id, content_hash, kind, matched_value, context,
        source_url, source_metadata, severity, tenant_id, watchlist_id,
        web_layer, access_mode, collected_at, finding_class
    )
    VALUES (
        p_source_id, lower(p_content_hash), p_kind, left(p_matched_value,512),
        left(p_context,2000), left(p_source_url,2048), coalesce(p_metadata,'{}'::jsonb),
        p_severity, p_tenant_id, p_watchlist_id, v_source_layer, v_source_access, now(),
        v_finding_class
    )
    ON CONFLICT (source_id, content_hash) DO UPDATE
      SET tenant_id = coalesce(excluded.tenant_id, public.dw_findings.tenant_id),
          watchlist_id = coalesce(excluded.watchlist_id, public.dw_findings.watchlist_id),
          severity = CASE
              WHEN public.dw_findings.severity = 'critical' OR excluded.severity = 'critical' THEN 'critical'
              WHEN public.dw_findings.severity = 'high' OR excluded.severity = 'high' THEN 'high'
              ELSE 'medium'
          END,
          source_metadata = excluded.source_metadata,
          finding_class = excluded.finding_class,
          web_layer = excluded.web_layer,
          access_mode = excluded.access_mode,
          collected_at = excluded.collected_at
    RETURNING id INTO v_finding;

    IF p_tenant_id IS NOT NULL AND p_watchlist_id IS NOT NULL THEN
        SELECT CASE
            WHEN w.severity = 'critical' OR p_severity = 'critical' THEN 'critical'
            WHEN w.severity = 'high' OR p_severity = 'high' THEN 'high'
            ELSE 'medium'
        END
          INTO v_severity
          FROM public.dw_watchlist w
         WHERE w.id = p_watchlist_id AND w.tenant_id = p_tenant_id;
        IF v_severity IS NULL THEN
            RAISE EXCEPTION 'watchlist disappeared during ingestion';
        END IF;

        v_title := CASE
            WHEN v_source_layer = 'dark' THEN 'Dark-web exposure detected'
            WHEN v_source_layer = 'breach_intel' THEN 'Breach exposure detected'
            WHEN v_source_layer = 'deep' THEN 'Deep-web exposure detected'
            WHEN p_kind = 'email' THEN 'Credential exposure detected'
            ELSE 'Monitored data exposure detected'
        END;

        INSERT INTO public.dw_alerts(tenant_id, watchlist_id, finding_id, kind, severity, title, summary)
        VALUES (p_tenant_id, p_watchlist_id, v_finding, p_kind, v_severity, v_title,
                left(coalesce(p_context,'Monitored identifier observed in an external source.'),2000))
        ON CONFLICT ON CONSTRAINT dw_alerts_watchlist_id_finding_id_key DO UPDATE
          SET severity = CASE
              WHEN public.dw_alerts.severity = 'critical' OR excluded.severity = 'critical' THEN 'critical'
              WHEN public.dw_alerts.severity = 'high' OR excluded.severity = 'high' THEN 'high'
              ELSE 'medium'
          END,
          summary = coalesce(excluded.summary, public.dw_alerts.summary)
        RETURNING id INTO v_alert;
        v_detection := NULL;
    END IF;

    RETURN QUERY SELECT v_finding, v_alert, v_detection;
END;
$function$;

COMMIT;
