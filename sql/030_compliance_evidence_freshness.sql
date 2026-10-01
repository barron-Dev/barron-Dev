-- Sentinel Compliance: evidence freshness and explicit collection coverage.
-- Stale or failed collectors must be visible to evaluators and auditors.

alter table public.compliance_collection_results
    add column if not exists valid_from timestamptz,
    add column if not exists freshness_window_seconds bigint,
    add column if not exists stale boolean not null default false;

alter table public.compliance_evidence
    add column if not exists freshness_window_seconds bigint,
    add column if not exists stale boolean not null default false;

create index if not exists compliance_collection_results_freshness_idx
    on public.compliance_collection_results (tenant_id, framework, control_id, valid_until, stale);

create index if not exists compliance_evidence_freshness_idx
    on public.compliance_evidence (tenant_id, framework, control_id, valid_until, stale);
