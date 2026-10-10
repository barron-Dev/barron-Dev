-- DW evidence-based triage: preserve detections, alert only above a bounded threshold.
-- Apply only after review and a staged migration plan; this file has not been applied.
ALTER TABLE public.dw_findings
    ADD COLUMN IF NOT EXISTS risk_score double precision NOT NULL DEFAULT 0.0
        CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
    ADD COLUMN IF NOT EXISTS risk_factors jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(risk_factors) = 'array'),
    ADD COLUMN IF NOT EXISTS alert_eligible boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.dw_findings.risk_score IS
    'Explainable deterministic prioritization score, not a probability of compromise.';
COMMENT ON COLUMN public.dw_findings.risk_factors IS
    'Allowlisted, non-secret factor names and bounded contributions used to prioritize this finding.';
COMMENT ON COLUMN public.dw_findings.alert_eligible IS
    'True only when an exact tenant watchlist match meets the configured risk threshold.';

ALTER TABLE public.dw_alerts
    ADD COLUMN IF NOT EXISTS risk_score double precision NOT NULL DEFAULT 0.0
        CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
    ADD COLUMN IF NOT EXISTS risk_factors jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(risk_factors) = 'array');

COMMENT ON COLUMN public.dw_alerts.risk_score IS
    'Risk score copied from the associated finding at alert creation/update time.';
COMMENT ON COLUMN public.dw_alerts.risk_factors IS
    'Explainable assessment factors supporting this alert.';

CREATE INDEX IF NOT EXISTS dw_findings_alert_eligible_idx
    ON public.dw_findings (tenant_id, first_seen DESC)
    WHERE tenant_id IS NOT NULL AND alert_eligible = true;

CREATE OR REPLACE FUNCTION public.record_dw_assessed_finding(
    p_source_id text,
    p_content_hash text,
    p_kind text,
    p_matched_value text,
    p_context text,
    p_severity text,
    p_source_url text,
    p_metadata jsonb,
    p_tenant_id uuid,
    p_watchlist_id uuid,
    p_risk_score double precision,
    p_risk_factors jsonb,
    p_alert_threshold double precision DEFAULT 0.72
) RETURNS TABLE(finding_id bigint, alert_id uuid, detection_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_finding bigint;
    v_alert uuid;
    v_detection uuid;
    v_watch_tenant uuid;
    v_verdict text;
    v_title text;
    v_severity text;
    v_alert_eligible boolean;
    v_reasons text[];
BEGIN
    IF p_source_id IS NULL OR length(trim(p_source_id)) = 0
       OR p_content_hash IS NULL OR length(trim(p_content_hash)) <> 64 THEN
        RAISE EXCEPTION 'invalid source or content hash';
    END IF;
    IF p_kind NOT IN ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id') THEN
        RAISE EXCEPTION 'invalid finding kind';
    END IF;
    IF p_severity NOT IN ('medium','high','critical') THEN
        RAISE EXCEPTION 'invalid finding severity';
    END IF;
    IF p_risk_score IS NULL OR p_risk_score < 0 OR p_risk_score > 1
       OR p_alert_threshold IS NULL OR p_alert_threshold < 0 OR p_alert_threshold > 1
       OR jsonb_typeof(coalesce(p_risk_factors, '[]'::jsonb)) <> 'array' THEN
        RAISE EXCEPTION 'invalid triage assessment';
    END IF;
    IF p_watchlist_id IS NOT NULL THEN
        SELECT tenant_id INTO v_watch_tenant
          FROM public.dw_watchlist WHERE id = p_watchlist_id;
        IF v_watch_tenant IS NULL OR p_tenant_id IS NULL OR v_watch_tenant <> p_tenant_id THEN
            RAISE EXCEPTION 'watchlist tenant mismatch';
        END IF;
    ELSIF p_tenant_id IS NOT NULL THEN
        RAISE EXCEPTION 'matched finding requires watchlist';
    END IF;

    v_alert_eligible := p_tenant_id IS NOT NULL
        AND p_watchlist_id IS NOT NULL
        AND p_risk_score >= p_alert_threshold;

    INSERT INTO public.dw_findings(
        source_id, content_hash, kind, matched_value, context, source_url,
        source_metadata, severity, tenant_id, watchlist_id, risk_score,
        risk_factors, alert_eligible
    )
    VALUES (
        p_source_id, p_content_hash, p_kind, left(p_matched_value, 512),
        left(p_context, 2000), left(p_source_url, 2048),
        coalesce(p_metadata, '{}'::jsonb), p_severity, p_tenant_id,
        p_watchlist_id, p_risk_score, coalesce(p_risk_factors, '[]'::jsonb),
        v_alert_eligible
    )
    ON CONFLICT (source_id, content_hash) DO UPDATE
      SET tenant_id = coalesce(excluded.tenant_id, dw_findings.tenant_id),
          watchlist_id = coalesce(excluded.watchlist_id, dw_findings.watchlist_id),
          risk_score = greatest(dw_findings.risk_score, excluded.risk_score),
          risk_factors = CASE
              WHEN excluded.risk_score >= dw_findings.risk_score THEN excluded.risk_factors
              ELSE dw_findings.risk_factors
          END,
          alert_eligible = dw_findings.alert_eligible OR excluded.alert_eligible
    RETURNING id INTO v_finding;

    IF p_tenant_id IS NOT NULL AND p_watchlist_id IS NOT NULL THEN
        IF v_alert_eligible THEN
            v_severity := p_severity;
            v_title := CASE p_kind
                WHEN 'email' THEN 'Credential exposure detected'
                WHEN 'domain' THEN 'Domain exposure detected'
                WHEN 'wallet' THEN 'Wallet exposure detected'
                WHEN 'api_key_hash' THEN 'Potential API key exposure detected'
                ELSE 'Monitored data exposure detected'
            END;
            INSERT INTO public.dw_alerts(
                tenant_id, watchlist_id, finding_id, kind, severity, title, summary,
            risk_score, risk_factors
            )
            VALUES (
                p_tenant_id, p_watchlist_id, v_finding, p_kind, v_severity,
                v_title, left(coalesce(p_context, 'Monitored identifier observed in an external source.'), 2000),
                p_risk_score, coalesce(p_risk_factors, '[]'::jsonb)
            )
            ON CONFLICT (watchlist_id, finding_id) DO UPDATE
              SET summary = excluded.summary,
                  risk_score = greatest(public.dw_alerts.risk_score, excluded.risk_score),
                  risk_factors = CASE
                      WHEN excluded.risk_score >= public.dw_alerts.risk_score THEN excluded.risk_factors
                      ELSE public.dw_alerts.risk_factors
                  END
            RETURNING id INTO v_alert;
        END IF;

        v_verdict := CASE WHEN p_risk_score >= 0.90 THEN 'malicious' ELSE 'suspicious' END;
        v_reasons := ARRAY['external_exposure', 'darkweb_watchlist_match']
            || ARRAY(
                SELECT left(item->>'factor', 80)
                FROM jsonb_array_elements(coalesce(p_risk_factors, '[]'::jsonb)) AS items(item)
                WHERE nullif(item->>'factor', '') IS NOT NULL
            );
        INSERT INTO public.detections(
            tenant_id, device_id, event_id, detector, score, verdict, reasons,
            evidence, mitre_technique, processed_by_playbooks, processed_by_autocase
        )
        VALUES (
            p_tenant_id, null, null, 'darkweb', p_risk_score, v_verdict, v_reasons,
            jsonb_build_object(
                'alert_id', v_alert, 'finding_id', v_finding,
                'source_id', p_source_id, 'kind', p_kind,
                'risk_score', p_risk_score, 'risk_factors', coalesce(p_risk_factors, '[]'::jsonb),
                'alert_eligible', v_alert_eligible, 'alert_threshold', p_alert_threshold
            ),
            'T1589', false, false
        )
        ON CONFLICT DO NOTHING
        RETURNING id INTO v_detection;
    END IF;

    RETURN QUERY SELECT v_finding, v_alert, v_detection;
END;
$$;

REVOKE ALL ON FUNCTION public.record_dw_assessed_finding(
    text,text,text,text,text,text,text,jsonb,uuid,uuid,double precision,jsonb,double precision
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_assessed_finding(
    text,text,text,text,text,text,text,jsonb,uuid,uuid,double precision,jsonb,double precision
) TO service_role;
