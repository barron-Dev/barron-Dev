-- Tenant-scoped Ransomwatch temporal observations referenced by request history.
-- Historical/future entries are review-only and never direct onion verification.
BEGIN;

CREATE TABLE IF NOT EXISTS public.dw_feed_temporal_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    watchlist_id uuid NOT NULL REFERENCES public.dw_watchlist(id) ON DELETE CASCADE,
    service_request_id uuid NOT NULL REFERENCES public.service_requests(id) ON DELETE CASCADE,
    source_id text NOT NULL DEFAULT 'ransomwatch' CHECK (source_id = 'ransomwatch'),
    entry_hash text NOT NULL CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
    observation_count integer NOT NULL DEFAULT 1 CHECK (observation_count >= 1),
    temporal_class text NOT NULL CHECK (temporal_class IN ('current_feed','historical_archive','future_dated')),
    published_at timestamptz,
    feed_observed_at timestamptz NOT NULL,
    feed_content_sha256 text CHECK (feed_content_sha256 IS NULL OR feed_content_sha256 ~ '^[0-9a-f]{64}$'),
    victim_name text NOT NULL CHECK (length(victim_name) BETWEEN 1 AND 512),
    group_name text,
    source_url text,
    label text NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, watchlist_id, source_id, entry_hash)
);

CREATE INDEX IF NOT EXISTS dw_feed_temporal_tenant_watchlist_time_idx
    ON public.dw_feed_temporal_observations (tenant_id, watchlist_id, temporal_class, published_at DESC);
CREATE INDEX IF NOT EXISTS dw_feed_temporal_request_idx
    ON public.dw_feed_temporal_observations (service_request_id, tenant_id);

ALTER TABLE public.dw_feed_temporal_observations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dw_feed_temporal_observations_tenant_select
    ON public.dw_feed_temporal_observations;
CREATE POLICY dw_feed_temporal_observations_tenant_select
    ON public.dw_feed_temporal_observations
    FOR SELECT TO authenticated
    USING (tenant_id = NULLIF(auth.jwt()->>'tenant_id','')::uuid);

REVOKE ALL ON public.dw_feed_temporal_observations FROM PUBLIC, anon;
REVOKE INSERT, UPDATE, DELETE ON public.dw_feed_temporal_observations FROM authenticated;
GRANT SELECT ON public.dw_feed_temporal_observations TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dw_feed_temporal_observations TO service_role;

COMMENT ON TABLE public.dw_feed_temporal_observations IS
  'Tenant/watchlist/request-scoped observations of Ransomwatch feed entries. Historical and future-dated rows are review/quarantine only, never direct onion verification.';

CREATE OR REPLACE FUNCTION public.record_dw_feed_temporal_observation(
    p_service_request_id uuid,
    p_expected_attempt integer,
    p_tenant_id uuid,
    p_watchlist_id uuid,
    p_source_id text,
    p_entry_hash text,
    p_temporal_class text,
    p_published_at timestamptz,
    p_feed_observed_at timestamptz,
    p_feed_content_sha256 text,
    p_victim_name text,
    p_group_name text,
    p_source_url text,
    p_label text,
    p_match_kind text,
    p_matched_value text
)
RETURNS TABLE(
    observation_id uuid,
    tenant_id uuid,
    watchlist_id uuid,
    service_request_id uuid,
    entry_hash text,
    temporal_class text,
    observation_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_request public.service_requests;
    v_watch public.dw_watchlist;
    v_org_tenant uuid;
    v_expected_kind text;
    v_request_value text;
    v_watch_value text;
    v_expected_class text;
    v_age_seconds numeric;
    v_observation public.dw_feed_temporal_observations;
BEGIN
    IF coalesce(auth.role(), '') <> 'service_role' THEN
        RAISE EXCEPTION 'ransomwatch_temporal_service_role_required';
    END IF;
    IF p_source_id IS DISTINCT FROM 'ransomwatch'
       OR p_entry_hash IS NULL OR p_entry_hash !~ '^[0-9a-f]{64}

       OR p_temporal_class NOT IN ('current_feed','historical_archive','future_dated')
       OR p_feed_observed_at IS NULL
       OR p_feed_content_sha256 IS NULL OR p_feed_content_sha256 !~ '^[0-9a-f]{64}

       OR length(trim(coalesce(p_victim_name,''))) = 0
       OR length(trim(coalesce(p_matched_value,''))) = 0
       OR p_match_kind NOT IN ('domain','company_name') THEN
        RAISE EXCEPTION 'ransomwatch_temporal_record_invalid';
    END IF;
    IF p_feed_observed_at > clock_timestamp() + interval '5 minutes'
       OR p_feed_observed_at < clock_timestamp() - interval '1 hour' THEN
        RAISE EXCEPTION 'ransomwatch_feed_observation_stale';
    END IF;

    IF p_published_at IS NULL THEN
        v_expected_class := 'historical_archive';
    ELSE
        v_age_seconds := extract(epoch FROM (p_feed_observed_at - p_published_at));
        IF v_age_seconds < -300 THEN
            v_expected_class := 'future_dated';
        ELSIF v_age_seconds <= 30 * 86400 THEN
            v_expected_class := 'current_feed';
        ELSE
            v_expected_class := 'historical_archive';
        END IF;
    END IF;
    IF p_temporal_class <> v_expected_class THEN
        RAISE EXCEPTION 'ransomwatch_temporal_class_mismatch';
    END IF;

    SELECT * INTO v_request
      FROM public.service_requests
     WHERE id = p_service_request_id
     FOR UPDATE;
    IF NOT FOUND
       OR v_request.service_key <> 'dark_web_monitoring'
       OR v_request.processing_state <> 'running'
       OR v_request.attempts <> p_expected_attempt
       OR v_request.locked_until IS NULL
       OR v_request.locked_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'ransomwatch_temporal_attempt_fence_rejected';
    END IF;

    SELECT tenant_id INTO v_org_tenant
      FROM public.customer_organizations
     WHERE id = v_request.organization_id;
    IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
        RAISE EXCEPTION 'ransomwatch_temporal_tenant_fence_rejected';
    END IF;

    SELECT * INTO v_watch
      FROM public.dw_watchlist
     WHERE id = p_watchlist_id AND tenant_id = p_tenant_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ransomwatch_temporal_watchlist_fence_rejected';
    END IF;

    v_expected_kind := CASE lower(coalesce(v_request.target_type,''))
        WHEN 'domain' THEN 'domain'
        WHEN 'url' THEN 'domain'
        WHEN 'brand' THEN 'company_name'
        ELSE NULL
    END;
    IF lower(coalesce(v_request.target_type,'')) IN ('domain','url') THEN
        v_request_value := lower(regexp_replace(
            regexp_replace(trim(coalesce(v_request.target,'')), '^https?://', '', 'i'),
            '[/#?].*
, ''
        ));
        v_request_value := regexp_replace(v_request_value, ':[0-9]+
, '');
        v_request_value := rtrim(v_request_value, '.');
    ELSE
        v_request_value := lower(trim(coalesce(v_request.target,'')));
    END IF;
    v_watch_value := lower(trim(coalesce(v_watch.value,'')));

    IF v_expected_kind IS NULL
       OR v_watch.kind <> v_expected_kind
       OR v_watch_value <> v_request_value
       OR p_match_kind <> v_expected_kind
       OR lower(trim(p_matched_value)) <> v_request_value THEN
        RAISE EXCEPTION 'ransomwatch_temporal_target_fence_rejected';
    END IF;

    INSERT INTO public.dw_feed_temporal_observations (
        tenant_id, watchlist_id, service_request_id, source_id, entry_hash,
        observation_count, temporal_class, published_at, feed_observed_at,
        feed_content_sha256, victim_name, group_name, source_url, label, last_seen_at
    ) VALUES (
        p_tenant_id, p_watchlist_id, p_service_request_id, p_source_id, p_entry_hash,
        1, p_temporal_class, p_published_at, p_feed_observed_at,
        p_feed_content_sha256, left(trim(p_victim_name),512),
        left(trim(coalesce(p_group_name,'unknown')),256),
        left(nullif(p_source_url,''),2048), left(trim(coalesce(p_label,'Ransomwatch temporal record')),256),
        clock_timestamp()
    )
    ON CONFLICT (tenant_id, watchlist_id, source_id, entry_hash) DO UPDATE SET
        service_request_id = excluded.service_request_id,
        observation_count = public.dw_feed_temporal_observations.observation_count + 1,
        temporal_class = excluded.temporal_class,
        published_at = excluded.published_at,
        feed_observed_at = excluded.feed_observed_at,
        feed_content_sha256 = excluded.feed_content_sha256,
        victim_name = excluded.victim_name,
        group_name = excluded.group_name,
        source_url = excluded.source_url,
        label = excluded.label,
        last_seen_at = clock_timestamp()
    RETURNING * INTO v_observation;

    RETURN QUERY SELECT v_observation.id, v_observation.tenant_id,
        v_observation.watchlist_id, v_observation.service_request_id,
        v_observation.entry_hash, v_observation.temporal_class,
        v_observation.observation_count;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_feed_temporal_observation(
    uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_feed_temporal_observation(
    uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) TO service_role;

COMMIT;
