-- Global, tenant-independent Ransomwatch feed archive used by the 15-minute
-- scheduler. This stores metadata only; current alerts still require exact
-- tenant matching and fresh-feed confirmation in the worker.

BEGIN;

CREATE TABLE IF NOT EXISTS public.dw_ransomwatch_temporal_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id text NOT NULL DEFAULT 'ransomwatch' CHECK (source_id = 'ransomwatch'),
  record_key text NOT NULL UNIQUE CHECK (record_key ~ '^[0-9a-f]{64}$'),
  source_url text,
  victim_name text NOT NULL CHECK (length(victim_name) BETWEEN 1 AND 512),
  victim_domain text,
  group_name text NOT NULL CHECK (length(group_name) BETWEEN 1 AND 256),
  published_at timestamptz,
  temporal_class text NOT NULL CHECK (temporal_class IN ('current_feed','historical_archive','future_dated')),
  feed_observed_at timestamptz NOT NULL,
  feed_response_date timestamptz NOT NULL,
  feed_age_seconds integer NOT NULL CHECK (feed_age_seconds BETWEEN 0 AND 3600),
  feed_content_sha256 text NOT NULL CHECK (feed_content_sha256 ~ '^[0-9a-f]{64}$'),
  feed_freshness_verified boolean NOT NULL CHECK (feed_freshness_verified),
  first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  observation_count bigint NOT NULL DEFAULT 1 CHECK (observation_count > 0)
);

CREATE INDEX IF NOT EXISTS dw_ransomwatch_temporal_class_time_idx
  ON public.dw_ransomwatch_temporal_records(temporal_class, published_at DESC, last_seen_at DESC);

ALTER TABLE public.dw_ransomwatch_temporal_records ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.dw_ransomwatch_temporal_records FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.dw_ransomwatch_temporal_records TO service_role;

CREATE OR REPLACE FUNCTION public.record_ransomwatch_temporal_records(
  p_records jsonb
) RETURNS TABLE (accepted_count integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_record jsonb;
  v_record_key text;
  v_source_url text;
  v_victim_name text;
  v_victim_domain text;
  v_group_name text;
  v_published_at timestamptz;
  v_temporal_class text;
  v_feed_observed_at timestamptz;
  v_feed_response_date timestamptz;
  v_feed_age_seconds integer;
  v_feed_content_sha256 text;
  v_freshness_verified boolean;
  v_accepted integer := 0;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'ransomwatch_archive_service_role_required';
  END IF;
  IF jsonb_typeof(p_records) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_records) > 5000 THEN
    RAISE EXCEPTION 'ransomwatch_archive_invalid_batch';
  END IF;

  FOR v_record IN SELECT value FROM jsonb_array_elements(p_records)
  LOOP
    BEGIN
      v_record_key := lower(coalesce(v_record->>'record_key', ''));
      v_source_url := nullif(v_record->>'source_url', '');
      v_victim_name := left(trim(coalesce(v_record->>'victim_name', '')), 512);
      v_victim_domain := nullif(left(trim(coalesce(v_record->>'victim_domain', '')), 253), '');
      v_group_name := left(trim(coalesce(v_record->>'group_name', 'unknown')), 256);
      v_published_at := nullif(v_record->>'published_at', '')::timestamptz;
      v_temporal_class := coalesce(v_record->>'temporal_class', '');
      v_feed_observed_at := nullif(v_record->>'feed_observed_at', '')::timestamptz;
      v_feed_response_date := nullif(v_record->>'feed_response_date', '')::timestamptz;
      v_feed_age_seconds := nullif(v_record->>'feed_age_seconds', '')::integer;
      v_feed_content_sha256 := lower(coalesce(v_record->>'feed_content_sha256', ''));
      v_freshness_verified := coalesce(v_record->>'feed_freshness_verified', 'false') = 'true';
    EXCEPTION WHEN others THEN
      RAISE EXCEPTION 'ransomwatch_archive_record_parse_failed';
    END;

    IF jsonb_typeof(v_record) IS DISTINCT FROM 'object'
       OR v_record_key !~ '^[0-9a-f]{64}$'
       OR v_victim_name = ''
       OR v_group_name = ''
       OR v_temporal_class NOT IN ('current_feed','historical_archive','future_dated')
       OR v_feed_observed_at IS NULL
       OR v_feed_response_date IS NULL
       OR v_feed_age_seconds IS NULL OR v_feed_age_seconds < 0 OR v_feed_age_seconds > 3600
       OR v_feed_content_sha256 !~ '^[0-9a-f]{64}$'
       OR NOT v_freshness_verified
       OR v_feed_observed_at < clock_timestamp() - interval '1 hour'
       OR v_feed_observed_at > clock_timestamp() + interval '5 minutes'
       OR v_feed_response_date < clock_timestamp() - interval '1 hour'
       OR v_feed_response_date > clock_timestamp() + interval '5 minutes'
       OR (v_source_url IS NOT NULL AND (length(v_source_url) > 2048 OR v_source_url !~ '^https?://')) THEN
      RAISE EXCEPTION 'ransomwatch_archive_record_invalid';
    END IF;

    IF v_temporal_class = 'current_feed' AND (
         v_published_at IS NULL
         OR v_published_at < v_feed_observed_at - interval '30 days'
         OR v_published_at > v_feed_observed_at + interval '5 minutes'
       ) THEN
      RAISE EXCEPTION 'ransomwatch_archive_current_window_invalid';
    ELSIF v_temporal_class = 'historical_archive' AND (
         v_published_at IS NOT NULL
         AND v_published_at >= v_feed_observed_at - interval '30 days'
       ) THEN
      RAISE EXCEPTION 'ransomwatch_archive_historical_window_invalid';
    ELSIF v_temporal_class = 'future_dated' AND (
         v_published_at IS NULL
         OR v_published_at <= v_feed_observed_at + interval '5 minutes'
       ) THEN
      RAISE EXCEPTION 'ransomwatch_archive_future_window_invalid';
    END IF;

    INSERT INTO public.dw_ransomwatch_temporal_records (
      record_key, source_url, victim_name, victim_domain, group_name,
      published_at, temporal_class, feed_observed_at, feed_response_date,
      feed_age_seconds, feed_content_sha256, feed_freshness_verified,
      first_seen_at, last_seen_at, observation_count
    ) VALUES (
      v_record_key, v_source_url, v_victim_name, v_victim_domain, v_group_name,
      v_published_at, v_temporal_class, v_feed_observed_at, v_feed_response_date,
      v_feed_age_seconds, v_feed_content_sha256, true,
      clock_timestamp(), clock_timestamp(), 1
    )
    ON CONFLICT (record_key) DO UPDATE
      SET source_url = EXCLUDED.source_url,
          victim_name = EXCLUDED.victim_name,
          victim_domain = EXCLUDED.victim_domain,
          group_name = EXCLUDED.group_name,
          published_at = EXCLUDED.published_at,
          temporal_class = EXCLUDED.temporal_class,
          feed_observed_at = EXCLUDED.feed_observed_at,
          feed_response_date = EXCLUDED.feed_response_date,
          feed_age_seconds = EXCLUDED.feed_age_seconds,
          feed_content_sha256 = EXCLUDED.feed_content_sha256,
          feed_freshness_verified = true,
          last_seen_at = clock_timestamp(),
          observation_count = public.dw_ransomwatch_temporal_records.observation_count + 1;

    v_accepted := v_accepted + 1;
  END LOOP;

  RETURN QUERY SELECT v_accepted;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_ransomwatch_temporal_records(jsonb)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_ransomwatch_temporal_records(jsonb)
  TO service_role;

COMMIT;
