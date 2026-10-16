-- Public, unauthenticated search sources. These adapters only inspect public search results.
-- No private groups, direct messages, or restricted feeds are accessed.
insert into public.dw_sources
  (id, name, kind, endpoint, enabled, poll_interval_seconds, web_layer, access_mode, last_status)
values
  ('bluesky_public', 'Bluesky public search', 'forum',
   'https://api.bsky.app/xrpc/app.bsky.feed.searchPosts',
   true, 900, 'surface', 'public', 'awaiting_first_pull'),
  ('reddit_public', 'Reddit public search RSS', 'forum',
   'https://www.reddit.com/search.rss',
   true, 900, 'surface', 'public', 'awaiting_first_pull'),
  ('hackernews_public', 'Hacker News public search', 'forum',
   'https://hn.algolia.com/api/v1/search_by_date',
   true, 900, 'surface', 'public', 'awaiting_first_pull'),
  ('lemmy_public', 'Lemmy public search', 'forum',
   'https://lemmy.ml/api/v3/search',
   true, 900, 'surface', 'public', 'awaiting_first_pull')
on conflict (id) do update set
  name = excluded.name,
  kind = excluded.kind,
  endpoint = excluded.endpoint,
  enabled = excluded.enabled,
  poll_interval_seconds = excluded.poll_interval_seconds,
  web_layer = excluded.web_layer,
  access_mode = excluded.access_mode;
