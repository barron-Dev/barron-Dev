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

COMMIT;
