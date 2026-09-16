-- Source copy of the applied Supabase migration: physical_operational_hardening.
-- Keep this file aligned with the migration recorded in Supabase.
--
-- The migration:
--   * changes customer physical tables to authenticated SELECT-only RLS;
--   * makes access/camera/IoT telemetry immutable after ingest;
--   * adds bounded correlation indexes;
--   * creates a DEFAULT partition for access_events so month rollover does not
--     stop ingestion before the next explicit monthly partition is installed.

DROP POLICY IF EXISTS physical_sites_tenant ON public.physical_sites;
DROP POLICY IF EXISTS badge_holders_tenant ON public.badge_holders;
DROP POLICY IF EXISTS access_events_tenant ON public.access_events;
DROP POLICY IF EXISTS camera_events_tenant ON public.camera_events;
DROP POLICY IF EXISTS iot_devices_tenant ON public.iot_devices;
DROP POLICY IF EXISTS iot_events_tenant ON public.iot_events;
DROP POLICY IF EXISTS pdc_tenant ON public.physical_digital_correlations;

CREATE POLICY physical_sites_tenant_select ON public.physical_sites FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());
CREATE POLICY badge_holders_tenant_select ON public.badge_holders FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());
CREATE POLICY access_events_tenant_select ON public.access_events FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());
CREATE POLICY camera_events_tenant_select ON public.camera_events FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());
CREATE POLICY iot_devices_tenant_select ON public.iot_devices FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());
CREATE POLICY iot_events_tenant_select ON public.iot_events FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());
CREATE POLICY pdc_tenant_select ON public.physical_digital_correlations FOR SELECT TO authenticated USING (tenant_id = public.current_tenant_id());

CREATE OR REPLACE FUNCTION public.physical_telemetry_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'physical telemetry is immutable';
END;
$$;
REVOKE ALL ON FUNCTION public.physical_telemetry_immutable() FROM public, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.physical_telemetry_immutable() TO service_role;

DROP TRIGGER IF EXISTS access_events_immutable ON public.access_events;
CREATE TRIGGER access_events_immutable BEFORE UPDATE OR DELETE ON public.access_events FOR EACH ROW EXECUTE FUNCTION public.physical_telemetry_immutable();
DROP TRIGGER IF EXISTS camera_events_immutable ON public.camera_events;
CREATE TRIGGER camera_events_immutable BEFORE UPDATE OR DELETE ON public.camera_events FOR EACH ROW EXECUTE FUNCTION public.physical_telemetry_immutable();
DROP TRIGGER IF EXISTS iot_events_immutable ON public.iot_events;
CREATE TRIGGER iot_events_immutable BEFORE UPDATE OR DELETE ON public.iot_events FOR EACH ROW EXECUTE FUNCTION public.physical_telemetry_immutable();

CREATE INDEX IF NOT EXISTS access_events_tenant_ts_idx ON public.access_events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS access_events_site_ts_idx ON public.access_events(site_id, ts DESC);
CREATE INDEX IF NOT EXISTS camera_events_tenant_ts_idx ON public.camera_events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS camera_events_site_ts_idx ON public.camera_events(site_id, ts DESC);
CREATE INDEX IF NOT EXISTS iot_events_tenant_ts_idx ON public.iot_events(tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS pdc_tenant_status_seen_idx ON public.physical_digital_correlations(tenant_id, status, last_seen DESC);

DO $$
BEGIN
  IF to_regclass('public.access_events_default') IS NULL THEN
    EXECUTE 'CREATE TABLE public.access_events_default PARTITION OF public.access_events DEFAULT';
  END IF;
END $$;
