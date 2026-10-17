-- Register Cyclothone's native, keyless public-onion collector.
-- Preserve access-method provenance explicitly in source and finding records.
ALTER TABLE public.dw_sources DROP CONSTRAINT IF EXISTS dw_sources_access_mode_check;
ALTER TABLE public.dw_sources ADD CONSTRAINT dw_sources_access_mode_check
    CHECK (access_mode = ANY (ARRAY['public','authenticated_customer','licensed_feed','customer_connector','tor_public_onion']));
ALTER TABLE public.dw_findings DROP CONSTRAINT IF EXISTS dw_findings_access_mode_check;
ALTER TABLE public.dw_findings ADD CONSTRAINT dw_findings_access_mode_check
    CHECK (access_mode = ANY (ARRAY['public','authenticated_customer','licensed_feed','customer_connector','tor_public_onion']));
ALTER TABLE public.dw_watchlist DROP CONSTRAINT IF EXISTS dw_watchlist_kind_check;
ALTER TABLE public.dw_watchlist ADD CONSTRAINT dw_watchlist_kind_check
    CHECK (kind = ANY (ARRAY['email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id','username','other']));
ALTER TABLE public.dw_findings DROP CONSTRAINT IF EXISTS dw_findings_kind_check;
ALTER TABLE public.dw_findings ADD CONSTRAINT dw_findings_kind_check
    CHECK (kind = ANY (ARRAY['email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id','username','other']));
CREATE TABLE IF NOT EXISTS public.dw_onion_seeds (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    url text NOT NULL UNIQUE,
    hostname text NOT NULL,
    seed_origin text NOT NULL DEFAULT 'configured'
        CHECK (seed_origin = ANY (ARRAY['configured','discovered'])),
    discovered_from text,
    status text NOT NULL DEFAULT 'candidate'
        CHECK (status = ANY (ARRAY['candidate','checked','failed','disabled'])),
    last_status text,
    last_checked timestamptz,
    last_response_sha256 text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dw_onion_seeds_status_checked_idx
    ON public.dw_onion_seeds (status, last_checked DESC);
ALTER TABLE public.dw_onion_seeds ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.dw_onion_seeds FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.dw_onion_seeds TO service_role;

-- The initial insert enables the native collector, but re-running this migration
-- must not override an operator's later decision to disable the source.
-- A registry row never proves Tor or any seed is reachable.
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
