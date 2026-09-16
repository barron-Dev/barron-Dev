-- Federation operational hardening.
-- Keep administrative trust_level separate from observed reputation.
-- Prevent duplicate platform/external peer identities and accelerate tenant-scoped exports.

create unique index if not exists uq_federation_peers_external_id
    on public.federation_peers (external_id)
    where external_id is not null;

create index if not exists idx_fed_indicators_source_tenant_last_seen
    on public.fed_indicators (source_tenant, last_seen desc)
    where source_tenant is not null and whitelisted = false;

create index if not exists idx_fed_indicator_observations_peer
    on public.fed_indicator_observations (peer_id, last_seen desc);

create index if not exists idx_fed_trust_edges_from_reputation
    on public.fed_trust_edges (from_peer_id, reputation desc);

-- Federation RPCs remain backend-only. Explicitly revoke from the client roles
-- so future grants cannot accidentally inherit execution through PUBLIC.
revoke all on function public.upsert_fed_indicator(uuid, uuid, text, text, text, text, text, real)
    from public, anon, authenticated;
revoke all on function public.record_fed_peer_result(uuid, uuid, boolean)
    from public, anon, authenticated;
revoke all on function public.recompute_peer_reputation(uuid)
    from public, anon, authenticated;

grant execute on function public.upsert_fed_indicator(uuid, uuid, text, text, text, text, text, real)
    to service_role;
grant execute on function public.record_fed_peer_result(uuid, uuid, boolean)
    to service_role;
grant execute on function public.recompute_peer_reputation(uuid)
    to service_role;
