-- Add public social/community sources to the customer Dark Web workflow.
-- This migration registers connectors; it does not claim they are reachable until
-- a real request records a successful provider check.
BEGIN;

INSERT INTO public.dw_sources
    (id, name, kind, endpoint, auth_ref, enabled, last_status, poll_interval_seconds)
VALUES
    ('bluesky_public', 'Bluesky public search', 'custom',
     'https://api.bsky.app/xrpc/app.bsky.feed.searchPosts', NULL, true, 'not_checked', 900),
    ('reddit_public', 'Reddit public search', 'forum',
     'https://oauth.reddit.com/search', 'CYCLOTHONE_REDDIT_CLIENT_ID,CYCLOTHONE_REDDIT_CLIENT_SECRET', true, 'not_checked', 900),
    ('hackernews_public', 'Hacker News public search', 'forum',
     'https://hn.algolia.com/api/v1/search_by_date', NULL, true, 'not_checked', 900),
    ('lemmy_public', 'Lemmy public search', 'forum',
     'https://lemmy.ml/api/v3/search', NULL, true, 'not_checked', 900)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    kind = EXCLUDED.kind,
    endpoint = EXCLUDED.endpoint,
    enabled = true,
    last_status = CASE
        WHEN public.dw_sources.last_pull_at IS NULL THEN 'not_checked'
        ELSE public.dw_sources.last_status
    END;

-- HIBP is intentionally excluded from Cyclothone's target source set.
UPDATE public.dw_sources
SET enabled = false,
    last_status = 'disabled_not_in_source_plan'
WHERE id = 'hibp';

-- The collector now uses the Pastebin.ca public JSON feed. Enable it, but leave
-- last_status as not_checked until a real collection attempt succeeds.
UPDATE public.dw_sources
SET enabled = true,
    endpoint = 'https://pastebin.ca/api/v1/feed?limit=20',
    last_status = CASE WHEN last_pull_at IS NULL THEN 'not_checked' ELSE last_status END
WHERE id = 'pastebin_public';

COMMIT;
