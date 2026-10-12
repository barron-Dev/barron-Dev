-- Register Meta public-content providers for explicit, permission-scoped checks.
-- Credentials stay in Railway runtime variables; never store access tokens here.
INSERT INTO public.dw_sources
    (id, name, kind, endpoint, auth_ref, enabled, poll_interval_seconds, web_layer, access_mode)
VALUES
    ('instagram_public', 'Instagram public hashtag media', 'social_public',
     'https://graph.facebook.com/v26.0/{ig-user-id}/ig_hashtag_search', NULL, TRUE, 1800, 'surface', 'public'),
    ('facebook_public', 'Facebook public Page posts', 'social_public',
     'https://graph.facebook.com/v26.0/{page-id}/posts', NULL, TRUE, 1800, 'surface', 'public')
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    kind = EXCLUDED.kind,
    endpoint = EXCLUDED.endpoint,
    poll_interval_seconds = EXCLUDED.poll_interval_seconds,
    web_layer = EXCLUDED.web_layer,
    access_mode = EXCLUDED.access_mode;
