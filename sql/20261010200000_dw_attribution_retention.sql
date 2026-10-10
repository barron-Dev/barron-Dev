-- Bounded retention for delivered alert transport records. Attribution assessments and
-- evidence hashes remain available for investigation/legal readiness until an explicit
-- tenant retention policy is approved; this function does not delete them.
create or replace function public.purge_dw_attribution_delivery_history(p_retention_days integer default 90)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_deleted integer;
begin
  delete from public.dw_attribution_alert_outbox
  where dispatched_at is not null
    and dispatched_at < now() - make_interval(days => greatest(30, least(coalesce(p_retention_days,90), 365)));
  get diagnostics v_deleted = row_count;
  return v_deleted;
end $$;
revoke all on function public.purge_dw_attribution_delivery_history(integer) from public, anon, authenticated;
grant execute on function public.purge_dw_attribution_delivery_history(integer) to service_role;
