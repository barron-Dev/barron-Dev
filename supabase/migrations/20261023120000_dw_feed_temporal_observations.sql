-- Tenant-scoped temporal observations for the public Ransomwatch aggregator.
-- Current feed matches, older archive matches, and future-dated quarantine share
-- one stable entry identity; this is not proof of direct onion access.

BEGIN;

CREATE TABLE IF NOT EXISTS public.dw_feed_temporal_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  watchlist_id uuid NOT NULL REFERENCES public.dw_watchlist(id) ON DELETE CASCADE,
  service_request_id uuid NOT NULL REFERENCES public.service_requests(id) ON DELETE CASCADE,
  source_id text NOT NULL DEFAULT 'ransomwatch' CHECK (source_id = 'ransomwatch'),
  entry_hash text NOT NULL CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
  temporal_class text NOT NULL CHECK (temporal_class IN ('current_feed','historical_archive','future_dated')),
  published_at timestamptz,
  feed_observed_at timestamptz NOT NULL,
  feed_content_sha256 text NOT NULL CHECK (feed_content_sha256 ~ '^[0-9a-f]{64}$'),
  victim_name text NOT NULL CHECK (length(victim_name) BETWEEN 1 AND 512),
  group_name text NOT NULL CHECK (length(group_name) BETWEEN 1 AND 256),
  source_url text,
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 256),
  match_kind text NOT NULL,
  matched_value text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  observation_count bigint NOT NULL DEFAULT 1 CHECK (observation_count > 0),
  UNIQUE (tenant_id, watchlist_id, source_id, entry_hash)
);

CREATE INDEX IF NOT EXISTS dw_feed_temporal_observations_tenant_watch_time_idx
  ON public.dw_feed_temporal_observations
     (tenant_id, watchlist_id, temporal_class, last_seen_at DESC);

ALTER TABLE public.dw_feed_temporal_observations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.dw_feed_temporal_observations FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.dw_feed_temporal_observations TO service_role;

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
) RETURNS TABLE (
  observation_id uuid,
  service_request_id uuid,
  tenant_id uuid,
  watchlist_id uuid,
  entry_hash text,
  temporal_class text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_request public.service_requests;
  v_org_tenant uuid;
  v_watch public.dw_watchlist;
  v_observation public.dw_feed_temporal_observations;
  v_expected_kind text;
  v_request_value text;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'ransomwatch_temporal_service_role_required';
  END IF;

  IF p_source_id IS DISTINCT FROM 'ransomwatch'
     OR p_entry_hash IS NULL OR p_entry_hash !~ '^[0-9a-f]{64}$'
     OR p_feed_content_sha256 IS NULL OR p_feed_content_sha256 !~ '^[0-9a-f]{64}$'
     OR p_temporal_class NOT IN ('current_feed','historical_archive','future_dated')
     OR p_feed_observed_at IS NULL
     OR p_feed_observed_at > clock_timestamp() + interval '5 minutes'
     OR p_victim_name IS NULL OR length(trim(p_victim_name)) NOT BETWEEN 1 AND 512
     OR p_group_name IS NULL OR length(trim(p_group_name)) NOT BETWEEN 1 AND 256
     OR p_label IS NULL OR length(trim(p_label)) NOT BETWEEN 1 AND 256
     OR p_match_kind IS NULL OR p_matched_value IS NULL OR length(trim(p_matched_value)) = 0
     OR (p_source_url IS NOT NULL AND (
          length(p_source_url) > 2048
          OR p_source_url !~ '^https?://'
        )) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_invalid_payload';
  END IF;

  IF p_temporal_class = 'current_feed' AND (
       p_published_at IS NULL
       OR p_published_at < p_feed_observed_at - interval '30 days'
       OR p_published_at > p_feed_observed_at + interval '5 minutes'
       OR p_feed_observed_at < clock_timestamp() - interval '1 hour'
     ) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_current_window_rejected';
  ELSIF p_temporal_class = 'historical_archive' AND (
       p_published_at IS NOT NULL
       AND p_published_at >= p_feed_observed_at - interval '30 days'
     ) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_historical_window_rejected';
  ELSIF p_temporal_class = 'future_dated' AND (
       p_published_at IS NULL
       OR p_published_at <= p_feed_observed_at + interval '5 minutes'
     ) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_future_window_rejected';
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
    RAISE EXCEPTION 'ransomwatch_temporal_target_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*

  IF NOT EXISTS (
    SELECT 1 FROM public.dw_sources
     WHERE id = 'ransomwatch' AND enabled = true
  ) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_source_disabled';
  END IF;

  INSERT INTO public.dw_feed_temporal_observations (
    tenant_id, watchlist_id, service_request_id, source_id, entry_hash,
    temporal_class, published_at, feed_observed_at, feed_content_sha256,
    victim_name, group_name, source_url, label, match_kind, matched_value,
    first_seen_at, last_seen_at, observation_count
  ) VALUES (
    p_tenant_id, p_watchlist_id, p_service_request_id, 'ransomwatch', p_entry_hash,
    p_temporal_class, p_published_at, p_feed_observed_at, p_feed_content_sha256,
    left(trim(p_victim_name), 512), left(trim(p_group_name), 256),
    left(p_source_url, 2048), left(trim(p_label), 256), p_match_kind,
    left(trim(p_matched_value), 512), clock_timestamp(), clock_timestamp(), 1
  )
  ON CONFLICT (tenant_id, watchlist_id, source_id, entry_hash) DO UPDATE
    SET service_request_id = EXCLUDED.service_request_id,
        temporal_class = EXCLUDED.temporal_class,
        published_at = EXCLUDED.published_at,
        feed_observed_at = EXCLUDED.feed_observed_at,
        feed_content_sha256 = EXCLUDED.feed_content_sha256,
        victim_name = EXCLUDED.victim_name,
        group_name = EXCLUDED.group_name,
        source_url = EXCLUDED.source_url,
        label = EXCLUDED.label,
        match_kind = EXCLUDED.match_kind,
        matched_value = EXCLUDED.matched_value,
        last_seen_at = clock_timestamp(),
        observation_count = public.dw_feed_temporal_observations.observation_count + 1
  RETURNING * INTO v_observation;

  RETURN QUERY SELECT
    v_observation.id,
    v_observation.service_request_id,
    v_observation.tenant_id,
    v_observation.watchlist_id,
    v_observation.entry_hash,
    v_observation.temporal_class;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_feed_temporal_observation(
  uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_feed_temporal_observation(
  uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) TO service_role;

COMMIT;
, ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+

  IF NOT EXISTS (
    SELECT 1 FROM public.dw_sources
     WHERE id = 'ransomwatch' AND enabled = true
  ) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_source_disabled';
  END IF;

  INSERT INTO public.dw_feed_temporal_observations (
    tenant_id, watchlist_id, service_request_id, source_id, entry_hash,
    temporal_class, published_at, feed_observed_at, feed_content_sha256,
    victim_name, group_name, source_url, label, match_kind, matched_value,
    first_seen_at, last_seen_at, observation_count
  ) VALUES (
    p_tenant_id, p_watchlist_id, p_service_request_id, 'ransomwatch', p_entry_hash,
    p_temporal_class, p_published_at, p_feed_observed_at, p_feed_content_sha256,
    left(trim(p_victim_name), 512), left(trim(p_group_name), 256),
    left(p_source_url, 2048), left(trim(p_label), 256), p_match_kind,
    left(trim(p_matched_value), 512), clock_timestamp(), clock_timestamp(), 1
  )
  ON CONFLICT (tenant_id, watchlist_id, source_id, entry_hash) DO UPDATE
    SET service_request_id = EXCLUDED.service_request_id,
        temporal_class = EXCLUDED.temporal_class,
        published_at = EXCLUDED.published_at,
        feed_observed_at = EXCLUDED.feed_observed_at,
        feed_content_sha256 = EXCLUDED.feed_content_sha256,
        victim_name = EXCLUDED.victim_name,
        group_name = EXCLUDED.group_name,
        source_url = EXCLUDED.source_url,
        label = EXCLUDED.label,
        match_kind = EXCLUDED.match_kind,
        matched_value = EXCLUDED.matched_value,
        last_seen_at = clock_timestamp(),
        observation_count = public.dw_feed_temporal_observations.observation_count + 1
  RETURNING * INTO v_observation;

  RETURN QUERY SELECT
    v_observation.id,
    v_observation.service_request_id,
    v_observation.tenant_id,
    v_observation.watchlist_id,
    v_observation.entry_hash,
    v_observation.temporal_class;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_feed_temporal_observation(
  uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_feed_temporal_observation(
  uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) TO service_role;

COMMIT;
, '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;

  IF v_expected_kind IS NULL
     OR lower(v_watch.kind) <> v_expected_kind
     OR lower(trim(v_watch.value)) <> v_request_value
     OR lower(trim(v_watch.value)) <> lower(trim(p_matched_value))
     OR lower(v_watch.kind) <> lower(p_match_kind) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_target_fence_rejected';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.dw_sources
     WHERE id = 'ransomwatch' AND enabled = true
  ) THEN
    RAISE EXCEPTION 'ransomwatch_temporal_source_disabled';
  END IF;

  INSERT INTO public.dw_feed_temporal_observations (
    tenant_id, watchlist_id, service_request_id, source_id, entry_hash,
    temporal_class, published_at, feed_observed_at, feed_content_sha256,
    victim_name, group_name, source_url, label, match_kind, matched_value,
    first_seen_at, last_seen_at, observation_count
  ) VALUES (
    p_tenant_id, p_watchlist_id, p_service_request_id, 'ransomwatch', p_entry_hash,
    p_temporal_class, p_published_at, p_feed_observed_at, p_feed_content_sha256,
    left(trim(p_victim_name), 512), left(trim(p_group_name), 256),
    left(p_source_url, 2048), left(trim(p_label), 256), p_match_kind,
    left(trim(p_matched_value), 512), clock_timestamp(), clock_timestamp(), 1
  )
  ON CONFLICT (tenant_id, watchlist_id, source_id, entry_hash) DO UPDATE
    SET service_request_id = EXCLUDED.service_request_id,
        temporal_class = EXCLUDED.temporal_class,
        published_at = EXCLUDED.published_at,
        feed_observed_at = EXCLUDED.feed_observed_at,
        feed_content_sha256 = EXCLUDED.feed_content_sha256,
        victim_name = EXCLUDED.victim_name,
        group_name = EXCLUDED.group_name,
        source_url = EXCLUDED.source_url,
        label = EXCLUDED.label,
        match_kind = EXCLUDED.match_kind,
        matched_value = EXCLUDED.matched_value,
        last_seen_at = clock_timestamp(),
        observation_count = public.dw_feed_temporal_observations.observation_count + 1
  RETURNING * INTO v_observation;

  RETURN QUERY SELECT
    v_observation.id,
    v_observation.service_request_id,
    v_observation.tenant_id,
    v_observation.watchlist_id,
    v_observation.entry_hash,
    v_observation.temporal_class;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_feed_temporal_observation(
  uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_feed_temporal_observation(
  uuid,integer,uuid,uuid,text,text,text,timestamptz,timestamptz,text,text,text,text,text,text,text
) TO service_role;

COMMIT;
