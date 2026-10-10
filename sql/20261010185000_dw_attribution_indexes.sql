-- Tenant-boundary and query indexes for attribution evidence/relationships.
alter table public.dw_actor_relationships add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
create index if not exists dw_actor_relationships_tenant_idx on public.dw_actor_relationships(tenant_id, updated_at desc);
alter table public.dw_attribution_assessments add column if not exists capec_ids jsonb not null default '[]'::jsonb;
alter table public.dw_attribution_assessments add column if not exists unified_kill_chain_phases jsonb not null default '[]'::jsonb;
create unique index if not exists dw_actor_evidence_tenant_cluster_hash_uidx
  on public.dw_actor_evidence(tenant_id, activity_cluster_id, evidence_hash, evidence_type);
create unique index if not exists dw_attribution_alert_outbox_assessment_event_uidx
  on public.dw_attribution_alert_outbox(tenant_id, assessment_id, event_type)
  where assessment_id is not null;
