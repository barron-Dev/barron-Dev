-- Additive schema foundation for the Cyclothone DW discovery queue worker.
-- The worker/RPC implementation is deliberately separate so it can be reviewed
-- against live grants and queue states before it is enabled.
begin;

alter table public.dw_source_discovery_queue
  add column if not exists lease_token uuid,
  add column if not exists lease_expires_at timestamptz,
  add column if not exists completed_at timestamptz,
  add column if not exists dead_lettered_at timestamptz;

-- Extend the existing live CHECK constraints for the worker's terminal states
-- and the new country/region discovery job kinds. Without this, the RPC and
-- catalog expansion would fail against the actual production schema.
alter table public.dw_source_discovery_queue
  drop constraint if exists dw_source_discovery_queue_queue_status_check,
  drop constraint if exists dw_source_discovery_queue_discovery_kind_check;

alter table public.dw_source_discovery_queue
  add constraint dw_source_discovery_queue_queue_status_check
    check (queue_status = any (array[
      'queued', 'processing', 'candidate_found', 'validated', 'rejected',
      'failed', 'deferred', 'completed', 'dead_letter'
    ])),
  add constraint dw_source_discovery_queue_discovery_kind_check
    check (discovery_kind = any (array[
      'official_source_discovery', 'onion_seed_discovery', 'feed_discovery',
      'source_health_recheck', 'official_criminal_justice_source_discovery',
      'official_corrections_prison_source_discovery',
      'public_cybercrime_advisory_source_discovery',
      'public_onion_threat_intel_candidate_discovery'
    ]));

create index if not exists dw_source_discovery_queue_claim_idx
  on public.dw_source_discovery_queue (next_attempt_at, created_at, id)
  where queue_status = 'queued';

create index if not exists dw_source_discovery_queue_expired_lease_idx
  on public.dw_source_discovery_queue (lease_expires_at)
  where queue_status = 'processing';

commit;
