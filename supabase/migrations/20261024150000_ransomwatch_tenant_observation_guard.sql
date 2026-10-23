-- Tighten tenant/watchlist/request binding for the existing temporal observation table.
-- Does not create a second archive table.
BEGIN;

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
