-- Ransomwatch is a public aggregator feed, not direct Tor access.
-- Preserve existing findings as historical where already classified, but stop
-- presenting the source and its old rows as native dark-web observations.
UPDATE public.dw_sources
SET web_layer = 'breach_intel',
    access_mode = 'public_feed',
    last_status = 'awaiting_current_feed_poll',
    poll_interval_seconds = 1800
WHERE id = 'ransomwatch';

UPDATE public.dw_findings
SET web_layer = 'breach_intel'
WHERE source_id = 'ransomwatch'
  AND web_layer IS DISTINCT FROM 'surface';

COMMENT ON COLUMN public.dw_findings.finding_class IS
  'Evidence class; Ransomwatch feed entries remain historical_archive unless the application exposes a fresh, dated current_feed entry as current surface-feed intelligence.';

-- Future alert titles must follow the finding's explicit class, not a legacy
-- web_layer='dark' value. Historical records remain visible as review-only.
UPDATE public.dw_alerts AS a
   SET title = CASE
     WHEN f.finding_class = 'current_breach_intel'
       THEN 'Breach exposure detected'
     ELSE 'Historical ransomware report — review only'
   END
  FROM public.dw_findings AS f
 WHERE a.finding_id = f.id
   AND f.source_id = 'ransomwatch';

