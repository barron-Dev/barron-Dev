-- Quarantine discovery work created for the legacy broad country/category matrix.
-- The current lease-fenced worker supports only the four explicitly typed discovery
-- kinds. Legacy jobs are not mapped onto those kinds because doing so would cause
-- unrelated category jobs or preloaded onion candidates to be processed by the wrong
-- adapter. Keep every row and its candidate/provenance fields for later reconciliation.
-- Apply only after reviewing the queue inventory and the preceding discovery migrations.

begin;

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

-- Do not delete candidate URLs or provenance, and do not rewrite old job kinds into
-- the new worker's supported kinds. New work is generated only by the reviewed
-- official criminal-justice / corrections / cyber-advisory / public onion-index
-- discovery migration, after its categories and catalog rows exist.

commit;
