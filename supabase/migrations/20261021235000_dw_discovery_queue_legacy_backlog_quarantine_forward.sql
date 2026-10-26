-- Forward-only repair for the live legacy discovery backlog.
-- Quarantine, never delete or relabel old job kinds as supported work.
-- Safe to run only when no unexpired legacy processing lease exists.
begin;

do $preflight$
begin
  if exists (
    select 1
    from public.dw_source_discovery_queue q
    where q.queue_status = 'processing'
      and q.discovery_kind in (
        'feed_discovery',
        'official_source_discovery',
        'onion_seed_discovery',
        'source_health_recheck'
      )
      and q.lease_expires_at >= now()
  ) then
    raise exception 'legacy discovery queue has an active lease; retry after the lease expires';
  end if;
end;
$preflight$;

with quarantined as (
  update public.dw_source_discovery_queue q
  set queue_status = 'deferred',
      last_error_code = 'legacy_worker_kind_not_supported',
      result_metadata = coalesce(q.result_metadata, '{}'::jsonb)
        || jsonb_build_object(
          'queue_disposition', 'quarantined_not_deleted',
          'queue_disposition_reason', 'legacy_discovery_kind_not_supported_by_current_worker',
          'original_discovery_kind', q.discovery_kind,
          'original_queue_status', q.queue_status,
          'quarantined_at', now(),
          'requeue_requires', 'explicit_adapter_and_review'
        ),
      lease_token = null,
      lease_expires_at = null,
      updated_at = now()
  where q.queue_status in ('queued', 'processing')
    and q.discovery_kind in (
      'feed_discovery',
      'official_source_discovery',
      'onion_seed_discovery',
      'source_health_recheck'
    )
  returning q.id
)
select count(*) as legacy_jobs_quarantined from quarantined;

commit;
