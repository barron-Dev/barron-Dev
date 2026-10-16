-- Cyclothone Dark Web: register active public ransomware aggregators.
-- This migration is additive. It preserves historical Ransomwatch records and source state.
insert into public.dw_sources (
    id, name, kind, endpoint, enabled, poll_interval_seconds, exposure_layer, access_mode
)
values
    ('ransomware_live', 'Ransomware.live', 'ransomware_leak',
     'https://api.ransomware.live/v2/recentvictims', true, 1800, 'dark', 'public'),
    ('ransomlook', 'RansomLook', 'ransomware_leak',
     'https://www.ransomlook.io/api/recent/100', true, 1800, 'dark', 'public')
on conflict (id) do update set
    name = excluded.name,
    kind = excluded.kind,
    endpoint = excluded.endpoint,
    poll_interval_seconds = excluded.poll_interval_seconds,
    exposure_layer = excluded.exposure_layer,
    access_mode = excluded.access_mode; -- preserve an operator-disabled source on re-apply
