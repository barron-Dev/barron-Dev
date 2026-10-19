-- Additive schema foundation for the Cyclothone DW discovery queue worker.
-- The worker/RPC implementation is deliberately separate so it can be reviewed
-- against live grants and queue states before it is enabled.
begin;

alter table public.dw_source_discovery_queue
  add column if not exists lease_token uuid,
  add column if not exists lease_expires_at timestamptz,
  add column if not exists completed_at timestamptz,
  add column if not exists dead_lettered_at timestamptz;

create index if not exists dw_source_discovery_queue_claim_idx
  on public.dw_source_discovery_queue (next_attempt_at, created_at, id)
  where queue_status = 'queued';

create index if not exists dw_source_discovery_queue_expired_lease_idx
  on public.dw_source_discovery_queue (lease_expires_at)
  where queue_status = 'processing';

commit;
