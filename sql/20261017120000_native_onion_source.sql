-- Register Cyclothone's native, keyless public-onion collector.
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
    access_mode = EXCLUDED.access_mode;
