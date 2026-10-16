-- Register YouTube public video metadata search as an explicit source.
-- The API key is runtime-injected as CYCLOTHONE_YOUTUBE_API_KEY; never store it in this table.
INSERT INTO public.dw_sources
    (id, name, kind, endpoint, auth_ref, enabled, poll_interval_seconds, web_layer, access_mode)
VALUES
    ('youtube_public', 'YouTube public video search', 'social_public',
     'https://www.googleapis.com/youtube/v3/search', NULL, TRUE, 1800, 'surface', 'public')
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    kind = EXCLUDED.kind,
    endpoint = EXCLUDED.endpoint,
    poll_interval_seconds = EXCLUDED.poll_interval_seconds,
    web_layer = EXCLUDED.web_layer,
    access_mode = EXCLUDED.access_mode;
