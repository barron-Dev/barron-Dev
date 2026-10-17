-- Reddit is explicitly excluded from Cyclothone source collection.
-- Preserve historical rows/evidence; only disable future source polling.
UPDATE public.dw_sources
SET enabled = false,
    last_status = 'excluded_by_policy'
WHERE id IN ('reddit', 'reddit_public', 'reddit_monitor');
