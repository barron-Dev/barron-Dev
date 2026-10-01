-- Keep source enablement authoritative in the runtime scheduler.
-- Pastebin's public feed currently returns HTTP 404 in production, so disable
-- that source until a verified replacement endpoint is configured.
UPDATE public.dw_sources
SET enabled = false,
    last_status = 'disabled'
WHERE id = 'pastebin_public';
