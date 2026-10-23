-- Tenant-scoped, non-alerting temporal archive for matched Ransomwatch feed observations.
-- Branch-only migration; apply through the approved release workflow after validation.
BEGIN;

CREATE TABLE IF NOT EXISTS public.dw_feed_temporal_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  watchlist_id uuid NOT NULL REFERENCES public.dw_watchlist(id) ON DELETE CASCADE,
  service_request_id uuid NOT NULL REFERENCES public.service_requests(id) ON DELETE CASCADE,
  source_id text NOT NULL CHECK (source_id = 'ransomwatch'),
  entry_hash text NOT NULL CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
  temporal_class text NOT NULL CHECK (temporal_class IN ('current_feed', 'historical_archive', 'future_dated')),
  published_at timestamptz,
  feed_observed_at timestamptz NOT NULL,
  feed_content_sha256 text CHECK (feed_content_sha256 IS NULL OR feed_content_sha256 ~ '^[0-9a-f]{64}$'),
  victim_name text NOT NULL CHECK (length(victim_name) BETWEEN 1 AND 500),
  group_name text,
  source_url text,
  label text NOT NULL,
  observation_count integer NOT NULL DEFAULT 1 CHECK (observation_count > 0),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, watchlist_id, source_id, entry_hash)
);

CREATE INDEX IF NOT EXISTS dw_feed_temporal_observations_tenant_time_idx
  ON public.dw_feed_temporal_observations (tenant_id, feed_observed_at DESC);
CREATE INDEX IF NOT EXISTS dw_feed_temporal_observations_watchlist_time_idx
  ON public.dw_feed_temporal_observations (watchlist_id, feed_observed_at DESC);

ALTER TABLE public.dw_feed_temporal_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dw_feed_temporal_observations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.dw_feed_temporal_observations FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON public.dw_feed_temporal_observations TO service_role;
DROP POLICY IF EXISTS dw_feed_temporal_observations_service_role ON public.dw_feed_temporal_observations;
CREATE POLICY dw_feed_temporal_observations_service_role
  ON public.dw_feed_temporal_observations
  FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.dw_feed_temporal_observation_tenant_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_watch_tenant uuid;
  v_org_tenant uuid;
BEGIN
  SELECT w.tenant_id INTO v_watch_tenant
    FROM public.dw_watchlist w WHERE w.id = NEW.watchlist_id;
  SELECT o.tenant_id INTO v_org_tenant
    FROM public.service_requests r
    JOIN public.customer_organizations o ON o.id = r.organization_id
   WHERE r.id = NEW.service_request_id;
  IF v_watch_tenant IS NULL OR v_org_tenant IS NULL
     OR NEW.tenant_id IS DISTINCT FROM v_watch_tenant
     OR NEW.tenant_id IS DISTINCT FROM v_org_tenant THEN
    RAISE EXCEPTION 'dw_feed_temporal_tenant_binding_rejected';
  END IF;
  RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_feed_temporal_observation_tenant_guard() FROM PUBLIC, anon, authenticated;
DROP TRIGGER IF EXISTS dw_feed_temporal_observation_tenant_guard ON public.dw_feed_temporal_observations;
CREATE TRIGGER dw_feed_temporal_observation_tenant_guard
  BEFORE INSERT OR UPDATE ON public.dw_feed_temporal_observations
  FOR EACH ROW EXECUTE FUNCTION public.dw_feed_temporal_observation_tenant_guard();

COMMIT;
