-- Public, unauthenticated social search adapters. These sources are limited to
-- publicly searchable posts and never access private groups, DMs, or restricted feeds.
insert into public.dw_sources
  (id, name, kind, endpoint, enabled, poll_interval_seconds, web_layer, access_mode, last_status)
values
  ('bluesky_public', 'Bluesky public search', 'forum',
   'https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts',
   true, 900, 'surface', 'public', 'awaiting_first_pull'),
  ('reddit_public', 'Reddit public search RSS', 'forum',
   'https://www.reddit.com/search.rss',
   true, 900, 'surface', 'public', 'awaiting_first_pull')
on conflict (id) do update set
  name = excluded.name,
  kind = excluded.kind,
  endpoint = excluded.endpoint,
  enabled = true,
  poll_interval_seconds = excluded.poll_interval_seconds,
  web_layer = excluded.web_layer,
  access_mode = excluded.access_mode;
