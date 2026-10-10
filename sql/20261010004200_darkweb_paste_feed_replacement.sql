-- Replace the retired Pastebin.com public-feed endpoint with the documented
-- Pastebin.ca public JSON feed. The previous endpoint returned HTTP 404 and
-- was intentionally disabled by sql/046_darkweb_source_enablement.sql.
-- This migration changes configuration only; it does not fabricate findings.
UPDATE public.dw_sources
SET name = 'Pastebin.ca public feed',
    kind = 'paste',
    endpoint = 'https://pastebin.ca/api/v1/feed?limit=20',
    enabled = true,
    last_pull_at = NULL,
    last_status = 'pending'
WHERE id = 'pastebin_public';
