-- Append-only collection observations and derived hourly buckets for shadow-only source silence detection.
-- This migration is intentionally not applied to production by this change.
CREATE TABLE IF NOT EXISTS public.dw_source_observations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id text NOT NULL REFERENCES public.dw_sources(id) ON DELETE RESTRICT,
    scope_key text NOT NULL CHECK (length(scope_key) BETWEEN 1 AND 240),
    observed_at timestamptz NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('checked', 'failed', 'unavailable')),
    cursor_value bigint,
    documents_new integer CHECK (documents_new IS NULL OR documents_new >= 0),
    latest_document_at timestamptz,
    count_complete boolean NOT NULL DEFAULT false,
    response_sha256 text CHECK (response_sha256 IS NULL OR response_sha256 ~ '^[0-9a-f]{64}$'),
    collector_version text NOT NULL CHECK (length(collector_version) BETWEEN 1 AND 100),
    error_code text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 8192),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (NOT count_complete OR (outcome = 'checked' AND documents_new IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_dw_source_observations_scope_time
    ON public.dw_source_observations (scope_key, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_dw_source_observations_source_time
    ON public.dw_source_observations (source_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS public.dw_source_silence_buckets (
    source_id text NOT NULL REFERENCES public.dw_sources(id) ON DELETE RESTRICT,
    scope_key text NOT NULL CHECK (length(scope_key) BETWEEN 1 AND 240),
    bucket_hour timestamptz NOT NULL,
    poll_count integer NOT NULL DEFAULT 0 CHECK (poll_count >= 0),
    complete_poll_count integer NOT NULL DEFAULT 0 CHECK (complete_poll_count >= 0),
    failed_poll_count integer NOT NULL DEFAULT 0 CHECK (failed_poll_count >= 0),
    documents_new_sum integer NOT NULL DEFAULT 0 CHECK (documents_new_sum >= 0),
    last_document_at timestamptz,
    last_observed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_key, bucket_hour),
    CHECK (complete_poll_count <= poll_count),
    CHECK (failed_poll_count <= poll_count)
);
CREATE INDEX IF NOT EXISTS idx_dw_source_silence_buckets_scope_hour
    ON public.dw_source_silence_buckets (scope_key, bucket_hour DESC);

CREATE TABLE IF NOT EXISTS public.dw_source_silence_scores (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id text NOT NULL REFERENCES public.dw_sources(id) ON DELETE RESTRICT,
    scope_key text NOT NULL CHECK (length(scope_key) BETWEEN 1 AND 240),
    evaluated_at timestamptz NOT NULL DEFAULT now(),
    last_document_at timestamptz,
    baseline_start timestamptz,
    baseline_end timestamptz,
    baseline_bucket_count integer NOT NULL DEFAULT 0 CHECK (baseline_bucket_count >= 0),
    expected_rate_per_hour double precision,
    dispersion_size double precision,
    gap_hours double precision,
    p_value double precision CHECK (p_value IS NULL OR (p_value >= 0 AND p_value <= 1)),
    state text NOT NULL CHECK (state IN ('monitoring_unavailable', 'insufficient_baseline', 'no_expected_activity', 'normal', 'silence_candidate')),
    shadow_only boolean NOT NULL DEFAULT true CHECK (shadow_only),
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 8192),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dw_source_silence_scores_scope_time
    ON public.dw_source_silence_scores (scope_key, evaluated_at DESC);

ALTER TABLE public.dw_source_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dw_source_silence_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dw_source_silence_scores ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON public.dw_source_observations, public.dw_source_silence_buckets, public.dw_source_silence_scores FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.dw_source_observations TO service_role;
GRANT SELECT ON public.dw_source_silence_buckets TO service_role;
GRANT SELECT, INSERT ON public.dw_source_silence_scores TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.dw_source_observations_id_seq TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.dw_source_silence_scores_id_seq TO service_role;

CREATE OR REPLACE FUNCTION public.reject_dw_silence_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'Cyclothone source observation and silence score ledgers are append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_dw_source_observations_append_only ON public.dw_source_observations;
CREATE TRIGGER trg_dw_source_observations_append_only
BEFORE UPDATE OR DELETE ON public.dw_source_observations
FOR EACH ROW EXECUTE FUNCTION public.reject_dw_silence_ledger_mutation();

DROP TRIGGER IF EXISTS trg_dw_source_silence_scores_append_only ON public.dw_source_silence_scores;
CREATE TRIGGER trg_dw_source_silence_scores_append_only
BEFORE UPDATE OR DELETE ON public.dw_source_silence_scores
FOR EACH ROW EXECUTE FUNCTION public.reject_dw_silence_ledger_mutation();

CREATE OR REPLACE FUNCTION public.record_dw_source_observation(
    p_source_id text,
    p_scope_key text,
    p_observed_at timestamptz,
    p_outcome text,
    p_cursor_value bigint,
    p_documents_new integer,
    p_latest_document_at timestamptz,
    p_count_complete boolean,
    p_response_sha256 text,
    p_collector_version text,
    p_error_code text,
    p_metadata jsonb
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_id bigint;
    v_hour timestamptz;
BEGIN
    IF p_outcome IS NULL OR p_outcome NOT IN ('checked', 'failed', 'unavailable') THEN
        RAISE EXCEPTION 'invalid source observation outcome';
    END IF;
    IF p_scope_key IS NULL OR length(p_scope_key) NOT BETWEEN 1 AND 240 OR left(p_scope_key, length(p_source_id) + 1) <> (p_source_id || ':') THEN
        RAISE EXCEPTION 'invalid source observation scope';
    END IF;
    IF p_documents_new IS NOT NULL AND p_documents_new < 0 THEN
        RAISE EXCEPTION 'invalid document count';
    END IF;
    IF p_count_complete AND (p_outcome <> 'checked' OR p_documents_new IS NULL) THEN
        RAISE EXCEPTION 'complete counts require checked outcome and a count';
    END IF;
    IF p_response_sha256 IS NOT NULL AND p_response_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid response digest';
    END IF;
    IF p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object' OR octet_length(p_metadata::text) > 8192 THEN
        RAISE EXCEPTION 'invalid observation metadata';
    END IF;

    v_hour := date_trunc('hour', p_observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    INSERT INTO public.dw_source_observations (
        source_id, scope_key, observed_at, outcome, cursor_value,
        documents_new, latest_document_at, count_complete,
        response_sha256, collector_version, error_code, metadata
    ) VALUES (
        p_source_id, p_scope_key, p_observed_at, p_outcome, p_cursor_value,
        p_documents_new, p_latest_document_at, p_count_complete,
        p_response_sha256, p_collector_version, p_error_code, p_metadata
    ) RETURNING id INTO v_id;

    INSERT INTO public.dw_source_silence_buckets AS existing (
        source_id, scope_key, bucket_hour, poll_count, complete_poll_count,
        failed_poll_count, documents_new_sum, last_document_at, last_observed_at, updated_at
    ) VALUES (
        p_source_id, p_scope_key, v_hour, 1,
        CASE WHEN p_count_complete THEN 1 ELSE 0 END,
        CASE WHEN p_outcome IN ('failed', 'unavailable') THEN 1 ELSE 0 END,
        CASE WHEN p_count_complete THEN p_documents_new ELSE 0 END,
        p_latest_document_at, p_observed_at, now()
    )
    ON CONFLICT (scope_key, bucket_hour) DO UPDATE SET
        poll_count = existing.poll_count + 1,
        complete_poll_count = existing.complete_poll_count
            + CASE WHEN p_count_complete THEN 1 ELSE 0 END,
        failed_poll_count = existing.failed_poll_count
            + CASE WHEN p_outcome IN ('failed', 'unavailable') THEN 1 ELSE 0 END,
        documents_new_sum = existing.documents_new_sum
            + CASE WHEN p_count_complete THEN p_documents_new ELSE 0 END,
        last_document_at = COALESCE(
            GREATEST(existing.last_document_at, p_latest_document_at),
            existing.last_document_at,
            p_latest_document_at
        ),
        last_observed_at = GREATEST(existing.last_observed_at, p_observed_at),
        updated_at = now();

    RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION public.record_dw_source_observation(text, text, timestamptz, text, bigint, integer, timestamptz, boolean, text, text, text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_observation(text, text, timestamptz, text, bigint, integer, timestamptz, boolean, text, text, text, jsonb) TO service_role, postgres;
