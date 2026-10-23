-- Durable temporal archive for the public Ransomwatch feed.
-- This stores source-level feed metadata only; it does not prove direct onion access.
BEGIN;

CREATE TABLE IF NOT EXISTS public.dw_ransomwatch_temporal_records (
    record_key text PRIMARY KEY CHECK (record_key ~ '^[0-9a-f]{64}$'),
    source_url text,
    victim_name text NOT NULL CHECK (length(victim_name) BETWEEN 1 AND 512),
    victim_domain text,
    group_name text NOT NULL CHECK (length(group_name) BETWEEN 1 AND 256),
    published_at timestamptz,
    temporal_class text NOT NULL CHECK (temporal_class IN ('current_feed','historical_archive','future_dated')),
    feed_observed_at timestamptz NOT NULL,
    feed_content_sha256 text NOT NULL CHECK (feed_content_sha256 ~ '^[0-9a-f]{64}$'),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    observed_count bigint NOT NULL DEFAULT 1 CHECK (observed_count >= 1),
    direct_onion_access_verified boolean NOT NULL DEFAULT false
        CHECK (direct_onion_access_verified = false)
);

CREATE INDEX IF NOT EXISTS dw_ransomwatch_temporal_class_published_idx
    ON public.dw_ransomwatch_temporal_records (temporal_class, published_at DESC);
CREATE INDEX IF NOT EXISTS dw_ransomwatch_temporal_domain_idx
    ON public.dw_ransomwatch_temporal_records (lower(victim_domain))
    WHERE victim_domain IS NOT NULL;
CREATE INDEX IF NOT EXISTS dw_ransomwatch_temporal_name_idx
    ON public.dw_ransomwatch_temporal_records (lower(victim_name));

ALTER TABLE public.dw_ransomwatch_temporal_records ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.dw_ransomwatch_temporal_records FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.dw_ransomwatch_temporal_records TO service_role;

CREATE OR REPLACE FUNCTION public.record_ransomwatch_temporal_records(p_records jsonb)
RETURNS TABLE(accepted_count integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
    v_item jsonb;
    v_count integer := 0;
    v_key text;
    v_victim text;
    v_group text;
    v_class text;
    v_feed_hash text;
    v_observed timestamptz;
    v_published timestamptz;
BEGIN
    IF coalesce(auth.role(), '') <> 'service_role' THEN
        RAISE EXCEPTION 'ransomwatch_temporal_service_role_required';
    END IF;
    IF jsonb_typeof(p_records) <> 'array' OR jsonb_array_length(p_records) > 5000 THEN
        RAISE EXCEPTION 'ransomwatch_temporal_batch_invalid';
    END IF;

    FOR v_item IN SELECT value FROM jsonb_array_elements(p_records)
    LOOP
        v_key := lower(coalesce(v_item->>'record_key',''));
        v_victim := left(trim(coalesce(v_item->>'victim_name','')),512);
        v_group := left(trim(coalesce(v_item->>'group_name','unknown')),256);
        v_class := coalesce(v_item->>'temporal_class','');
        v_feed_hash := lower(coalesce(v_item->>'feed_content_sha256',''));

        IF v_key !~ '^[0-9a-f]{64}$'
           OR v_victim = ''
           OR v_group = ''
           OR v_class NOT IN ('current_feed','historical_archive','future_dated')
           OR v_feed_hash !~ '^[0-9a-f]{64}$'
           OR coalesce(v_item->>'feed_observed_at','') = '' THEN
            RAISE EXCEPTION 'ransomwatch_temporal_record_invalid';
        END IF;

        BEGIN
            v_observed := (v_item->>'feed_observed_at')::timestamptz;
            v_published := nullif(v_item->>'published_at','')::timestamptz;
        EXCEPTION WHEN others THEN
            RAISE EXCEPTION 'ransomwatch_temporal_timestamp_invalid';
        END;

        INSERT INTO public.dw_ransomwatch_temporal_records (
            record_key, source_url, victim_name, victim_domain, group_name,
            published_at, temporal_class, feed_observed_at, feed_content_sha256,
            direct_onion_access_verified
        ) VALUES (
            v_key,
            left(nullif(v_item->>'source_url',''),2048),
            v_victim,
            left(nullif(v_item->>'victim_domain',''),253),
            v_group,
            v_published,
            v_class,
            v_observed,
            v_feed_hash,
            false
        )
        ON CONFLICT (record_key) DO UPDATE SET
            source_url = excluded.source_url,
            victim_name = excluded.victim_name,
            victim_domain = excluded.victim_domain,
            group_name = excluded.group_name,
            published_at = excluded.published_at,
            temporal_class = excluded.temporal_class,
            feed_observed_at = excluded.feed_observed_at,
            feed_content_sha256 = excluded.feed_content_sha256,
            last_seen_at = now(),
            observed_count = public.dw_ransomwatch_temporal_records.observed_count + 1,
            direct_onion_access_verified = false;
        v_count := v_count + 1;
    END LOOP;

    RETURN QUERY SELECT v_count;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_ransomwatch_temporal_records(jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_ransomwatch_temporal_records(jsonb) TO service_role;

COMMENT ON TABLE public.dw_ransomwatch_temporal_records IS
  'Global source-level temporal archive of public Ransomwatch feed entries. Never direct onion verification and never tenant-specific findings.';

COMMIT;
