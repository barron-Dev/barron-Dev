-- Cyclothone DW trust-boundary foundation (branch-only; do not apply to production yet).
-- Conservative by construction: no historical row is promoted to verified.
-- Evidence-backed verified findings remain blocked until a durable evidence model
-- and collector-to-evidence writer are implemented and reviewed.

BEGIN;

ALTER TABLE public.dw_findings
  ADD COLUMN IF NOT EXISTS finding_class text NOT NULL DEFAULT 'historical_archive';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.dw_findings'::regclass
       AND conname = 'dw_findings_finding_class_check'
  ) THEN
    ALTER TABLE public.dw_findings
      ADD CONSTRAINT dw_findings_finding_class_check
      CHECK (finding_class IN ('verified_live_darkweb', 'historical_archive', 'surface_public'))
      NOT VALID;
  END IF;
END $$;

-- Existing records remain historical_archive. Never infer verification from
-- a non-null URL, hash, metadata field, or legacy web_layer.
ALTER TABLE public.dw_findings
  VALIDATE CONSTRAINT dw_findings_finding_class_check;

ALTER TABLE public.dw_sources
  ADD COLUMN IF NOT EXISTS source_class text;

UPDATE public.dw_sources
   SET source_class = CASE id
     WHEN 'native_onion' THEN 'native_onion'
     WHEN 'telegram_public' THEN 'telegram_public'
     WHEN 'pastebin_public' THEN 'pastebin_public'
     WHEN 'bluesky_public' THEN 'bluesky_public'
     WHEN 'github_code' THEN 'github_code_search'
     WHEN 'github_code_search' THEN 'github_code_search'
     WHEN 'tiktok_commercial' THEN 'tiktok_commercial'
     WHEN 'ransomwatch' THEN 'historical_archive'
     WHEN 'reddit_public' THEN 'excluded'
     WHEN 'reddit' THEN 'excluded'
     WHEN 'hibp' THEN 'excluded'
     ELSE coalesce(source_class, 'unclassified')
   END
 WHERE source_class IS NULL;

ALTER TABLE public.dw_sources
  ALTER COLUMN source_class SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'public.dw_sources'::regclass
       AND conname = 'dw_sources_source_class_check'
  ) THEN
    ALTER TABLE public.dw_sources
      ADD CONSTRAINT dw_sources_source_class_check
      CHECK (source_class IN (
        'native_onion','telegram_public','pastebin_public','bluesky_public',
        'github_code_search','tiktok_commercial','historical_archive',
        'excluded','unclassified'
      )) NOT VALID;
  END IF;
END $$;

ALTER TABLE public.dw_sources
  VALIDATE CONSTRAINT dw_sources_source_class_check;

-- Source attempts are durable runtime outcomes, not configuration claims.
-- This table intentionally does not assert that any source has succeeded.
CREATE TABLE IF NOT EXISTS public.dw_source_attempts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source_id text NOT NULL REFERENCES public.dw_sources(id),
  attempted_at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL CHECK (status IN (
    'ok','unavailable_403','unavailable_missing_creds','unavailable_missing_seeds',
    'failed','timeout','disabled','historical_only'
  )),
  route_verified boolean NOT NULL DEFAULT false,
  hs_desc_content_received boolean NOT NULL DEFAULT false,
  descriptor_fetched boolean NOT NULL DEFAULT false,
  rendezvous_hop_verified boolean NOT NULL DEFAULT false,
  stream_circuit_bound boolean NOT NULL DEFAULT false,
  auth_ok boolean NOT NULL DEFAULT false,
  content_sha256 text,
  inspected_items integer NOT NULL DEFAULT 0 CHECK (inspected_items >= 0),
  error_code text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS dw_source_attempts_latest_idx
  ON public.dw_source_attempts(source_id, attempted_at DESC, id DESC);

-- Keep the ledger private until a reviewed writer RPC is added. The worker must
-- not gain direct table-write privileges as a side effect of this foundation.
ALTER TABLE public.dw_source_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.dw_source_attempts FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.dw_source_attempts TO service_role;

CREATE TABLE IF NOT EXISTS public.dw_source_type_requirements (
  source_class text PRIMARY KEY CHECK (source_class IN (
    'native_onion','telegram_public','pastebin_public','bluesky_public',
    'github_code_search','tiktok_commercial','historical_archive',
    'excluded','unclassified'
  )),
  requires_route_verified boolean NOT NULL,
  requires_hs_desc_content boolean NOT NULL,
  requires_descriptor_fetch boolean NOT NULL,
  requires_rendezvous_hop boolean NOT NULL,
  requires_stream_circuit_binding boolean NOT NULL,
  requires_auth boolean NOT NULL,
  max_age_seconds integer NOT NULL CHECK (max_age_seconds >= 0)
);

INSERT INTO public.dw_source_type_requirements
  (source_class, requires_route_verified, requires_hs_desc_content, requires_descriptor_fetch,
   requires_rendezvous_hop, requires_stream_circuit_binding, requires_auth, max_age_seconds)
VALUES
  ('native_onion', true, true, true, true, true, false, 86400),
  ('telegram_public', false, false, false, false, false, false, 86400),
  ('pastebin_public', false, false, false, false, false, false, 86400),
  ('bluesky_public', false, false, false, false, false, false, 86400),
  ('github_code_search', false, false, false, false, false, true, 86400),
  ('tiktok_commercial', false, false, false, false, false, true, 86400),
  ('historical_archive', false, false, false, false, false, false, 0),
  ('excluded', false, false, false, false, false, false, 0),
  ('unclassified', false, false, false, false, false, false, 0)
ON CONFLICT (source_class) DO NOTHING;

ALTER TABLE public.dw_source_type_requirements ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.dw_source_type_requirements FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.dw_source_type_requirements TO service_role;

CREATE OR REPLACE VIEW public.dw_source_effective_state AS
WITH latest AS (
  SELECT DISTINCT ON (a.source_id)
    a.source_id, a.attempted_at, a.status, a.route_verified,
    a.hs_desc_content_received, a.descriptor_fetched, a.rendezvous_hop_verified,
    a.stream_circuit_bound, a.auth_ok, a.content_sha256, a.inspected_items
  FROM public.dw_source_attempts a
  ORDER BY a.source_id, a.attempted_at DESC, a.id DESC
)
SELECT
  s.id AS source_id,
  s.name,
  s.source_class,
  s.enabled AS config_enabled,
  l.attempted_at AS last_attempt_at,
  l.status AS last_attempt_status,
  coalesce(l.route_verified, false) AS route_verified,
  coalesce(l.hs_desc_content_received, false) AS hs_desc_content_received,
  coalesce(l.descriptor_fetched, false) AS descriptor_fetched,
  coalesce(l.rendezvous_hop_verified, false) AS rendezvous_hop_verified,
  coalesce(l.stream_circuit_bound, false) AS stream_circuit_bound,
  coalesce(l.auth_ok, false) AS auth_ok,
  coalesce(l.inspected_items, 0) AS inspected_items,
  CASE
    WHEN NOT s.enabled THEN 'disabled'
    WHEN s.source_class IN ('historical_archive','excluded','unclassified') THEN
      CASE WHEN s.source_class = 'historical_archive' THEN 'historical_only'
           WHEN s.source_class = 'excluded' THEN 'excluded_by_policy'
           ELSE 'unclassified' END
    WHEN l.attempted_at IS NULL THEN 'never_checked'
    WHEN l.attempted_at < now() - make_interval(secs => r.max_age_seconds) THEN 'stale'
    WHEN r.requires_route_verified AND NOT coalesce(l.route_verified, false) THEN 'unverified_route'
    WHEN r.requires_hs_desc_content AND NOT coalesce(l.hs_desc_content_received, false) THEN 'hs_desc_content_unverified'
    WHEN r.requires_descriptor_fetch AND NOT coalesce(l.descriptor_fetched, false) THEN 'descriptor_unverified'
    WHEN r.requires_rendezvous_hop AND NOT coalesce(l.rendezvous_hop_verified, false) THEN 'rendezvous_hop_unverified'
    WHEN r.requires_stream_circuit_binding AND NOT coalesce(l.stream_circuit_bound, false) THEN 'stream_circuit_unbound'
    WHEN r.requires_auth AND NOT coalesce(l.auth_ok, false) THEN 'auth_unverified'
    WHEN l.status = 'ok' AND l.content_sha256 ~ '^[0-9a-f]{64}
    WHEN l.status = 'ok' THEN 'unverified_success'
    ELSE 'unavailable'
  END AS effective_state
FROM public.dw_sources s
LEFT JOIN latest l ON l.source_id = s.id
LEFT JOIN public.dw_source_type_requirements r ON r.source_class = s.source_class;

-- This view is only an operational read surface for the privileged service role.
REVOKE ALL ON TABLE public.dw_source_effective_state FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.dw_source_effective_state TO service_role;

-- Archived ransomware feed is never an active live check. Preserve rows and
-- provenance; this only disables future polling and corrects source taxonomy.
UPDATE public.dw_sources
   SET enabled = false,
       source_class = 'historical_archive',
       web_layer = 'breach_intel',
       last_status = 'historical_only_archived_feed',
       poll_interval_seconds = 604800
 WHERE id = 'ransomwatch';

COMMIT;
 AND l.inspected_items > 0
         AND (NOT r.requires_route_verified OR l.route_verified)
         AND (NOT r.requires_hs_desc_content OR l.hs_desc_content_received)
         AND (NOT r.requires_descriptor_fetch OR l.descriptor_fetched)
         AND (NOT r.requires_rendezvous_hop OR l.rendezvous_hop_verified)
         AND (NOT r.requires_stream_circuit_binding OR l.stream_circuit_bound)
         AND (NOT r.requires_auth OR l.auth_ok) THEN 'available'
    WHEN l.status = 'ok' THEN 'unverified_success'
    ELSE 'unavailable'
  END AS effective_state
FROM public.dw_sources s
LEFT JOIN latest l ON l.source_id = s.id
LEFT JOIN public.dw_source_type_requirements r ON r.source_class = s.source_class;

-- This view is only an operational read surface for the privileged service role.
REVOKE ALL ON TABLE public.dw_source_effective_state FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.dw_source_effective_state TO service_role;

-- Archived ransomware feed is never an active live check. Preserve rows and
-- provenance; this only disables future polling and corrects source taxonomy.
UPDATE public.dw_sources
   SET enabled = false,
       source_class = 'historical_archive',
       last_status = 'historical_only_archived_feed',
       poll_interval_seconds = 604800
 WHERE id = 'ransomwatch';

COMMIT;
