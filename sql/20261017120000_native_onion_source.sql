-- Register Cyclothone's native, keyless public-onion collector.
-- Preserve access-method provenance explicitly in source and finding records.
ALTER TABLE public.dw_sources DROP CONSTRAINT IF EXISTS dw_sources_access_mode_check;
ALTER TABLE public.dw_sources ADD CONSTRAINT dw_sources_access_mode_check
    CHECK (access_mode = ANY (ARRAY['public','authenticated_customer','licensed_feed','customer_connector','tor_public_onion']));
ALTER TABLE public.dw_findings DROP CONSTRAINT IF EXISTS dw_findings_access_mode_check;
ALTER TABLE public.dw_findings ADD CONSTRAINT dw_findings_access_mode_check
    CHECK (access_mode = ANY (ARRAY['public','authenticated_customer','licensed_feed','customer_connector','tor_public_onion']));
-- Enabling the registry row does not imply that Tor or any seed is reachable.
-- The request worker reports the source unavailable until a real scan succeeds.
INSERT INTO public.dw_sources
    (id, name, kind, endpoint, enabled, web_layer, access_mode, last_status, last_pull_at)
VALUES
    ('native_onion', 'Cyclothone Native Onion Crawler', 'forum', NULL, true,
     'dark', 'tor_public_onion', 'pending', NULL)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    kind = EXCLUDED.kind,
    web_layer = EXCLUDED.web_layer,
    access_mode = EXCLUDED.access_mode,
    enabled = true;
