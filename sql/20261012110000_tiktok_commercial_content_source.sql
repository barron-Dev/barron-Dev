-- Official TikTok Commercial Content API source.
-- This source covers public commercial/ad-library data (currently EU data), not
-- every organic video or arbitrary creator timeline.
insert into public.dw_sources
  (id, name, kind, endpoint, enabled, poll_interval_seconds, web_layer, access_mode, last_status)
values
  ('tiktok_commercial', 'TikTok Commercial Content API (EU ads)', 'social',
   'https://open.tiktokapis.com/v2/research/adlib/ad/query/',
   true, 900, 'surface', 'public', 'awaiting_api_credentials')
on conflict (id) do update set
  name = excluded.name,
  kind = excluded.kind,
  endpoint = excluded.endpoint,
  enabled = true,
  poll_interval_seconds = excluded.poll_interval_seconds,
  web_layer = excluded.web_layer,
  access_mode = excluded.access_mode;
