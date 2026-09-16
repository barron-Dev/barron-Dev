-- Federation reputation repair.
-- 029 defines the canonical reputation RPC, but production verification found
-- the live database missing it. Keep this migration idempotent and preserve the
-- separation between administrative trust_level and observed reputation.

create or replace function public.recompute_peer_reputation(p_peer uuid)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    accepted integer;
    rejected integer;
    poisoned integer;
    v_rep real;
begin
    if p_peer is null then
        raise exception 'peer is required';
    end if;

    select coalesce(sum(accepted_count), 0),
           coalesce(sum(rejected_count), 0)
      into accepted, rejected
      from public.fed_trust_edges
     where from_peer_id = p_peer;

    select count(*)::integer
      into poisoned
      from public.fed_poisoning_events
     where peer_id = p_peer
       and ts > now() - interval '30 days';

    if accepted + rejected = 0 then
        v_rep := 0.5;
    else
        v_rep := accepted::real / (accepted + rejected)::real;
    end if;

    v_rep := greatest(0.0, least(1.0,
        v_rep * (1.0 - least(poisoned * 0.1, 0.5))
    ));

    update public.federation_peers
       set reputation = v_rep
     where id = p_peer;
end;
$$;

revoke all on function public.recompute_peer_reputation(uuid)
    from public, anon, authenticated;
grant execute on function public.recompute_peer_reputation(uuid)
    to service_role;
