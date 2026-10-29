-- Source-only until full live migration-history reconciliation is complete.
-- Global reference data only. No tenant telemetry is exposed by these policies.
CREATE TABLE IF NOT EXISTS public.mdi_global_telecom_registry (
    mcc text NOT NULL CHECK (mcc ~ '^[0-9]{3}$'),
    mnc text NOT NULL CHECK (mnc ~ '^[0-9]{2,3}$'),
    country_iso text NOT NULL CHECK (country_iso ~ '^[A-Z]{2}$'),
    provider_name text NOT NULL CHECK (length(trim(provider_name)) > 0),
    source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    source_name text NOT NULL,
    source_url text,
    imported_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (mcc, mnc)
);
ALTER TABLE public.mdi_global_telecom_registry ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.mdi_global_telecom_registry FROM anon, authenticated;
GRANT SELECT ON public.mdi_global_telecom_registry TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.mdi_global_telecom_registry TO service_role;
DROP POLICY IF EXISTS mdi_global_telecom_registry_authenticated_read ON public.mdi_global_telecom_registry;
CREATE POLICY mdi_global_telecom_registry_authenticated_read
  ON public.mdi_global_telecom_registry FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS mdi_global_telecom_registry_service_role_all ON public.mdi_global_telecom_registry;
CREATE POLICY mdi_global_telecom_registry_service_role_all
  ON public.mdi_global_telecom_registry FOR ALL TO service_role USING (true) WITH CHECK (true);

-- These two relations are global threat-reference catalogs (no tenant_id column).
-- Read-only access is intentionally granted only to signed-in users; writes remain service-role-only.
GRANT SELECT ON public.mdi_threat_actors, public.mdi_actor_ttps TO authenticated;
DROP POLICY IF EXISTS mdi_threat_actors_authenticated_read ON public.mdi_threat_actors;
CREATE POLICY mdi_threat_actors_authenticated_read ON public.mdi_threat_actors
  FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS mdi_actor_ttps_authenticated_read ON public.mdi_actor_ttps;
CREATE POLICY mdi_actor_ttps_authenticated_read ON public.mdi_actor_ttps
  FOR SELECT TO authenticated USING (true);
