-- Sentinel security surface hardening, migration 039.
-- These tables are backend/service data and must never be directly accessible
-- by browser roles. RLS remains enabled; service_role is the only granted role.

revoke all on table public.access_events_2026_09 from anon, authenticated;
revoke all on table public.access_events_2026_10 from anon, authenticated;
revoke all on table public.access_events_default from anon, authenticated;
revoke all on table public.events_default from anon, authenticated;

revoke all on table public.fed_detection_matches from anon, authenticated;
revoke all on table public.fed_indicator_observations from anon, authenticated;
revoke all on table public.fed_indicators from anon, authenticated;
revoke all on table public.fed_poisoning_events from anon, authenticated;
revoke all on table public.fed_shares from anon, authenticated;
revoke all on table public.fed_trust_edges from anon, authenticated;
revoke all on table public.federation_peers from anon, authenticated;
revoke all on table public.intel_pull_log from anon, authenticated;
revoke all on table public.signing_keys from anon, authenticated;

grant all on table public.fed_detection_matches,
    public.fed_indicator_observations,
    public.fed_indicators,
    public.fed_poisoning_events,
    public.fed_shares,
    public.fed_trust_edges,
    public.federation_peers,
    public.intel_pull_log,
    public.signing_keys
    to service_role;

grant all on table public.access_events_2026_09,
    public.access_events_2026_10,
    public.access_events_default,
    public.events_default
    to service_role;
