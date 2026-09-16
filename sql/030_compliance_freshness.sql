-- Sentinel Compliance freshness and evidence coverage.
-- Freshness is distinct from the historical evidence period: a collector result
-- expires independently so a control cannot remain passing indefinitely.

alter table public.compliance_control_status
    add column if not exists evidence_valid_until timestamptz,
    add column if not exists freshness_status text not null default 'unknown'
        check (freshness_status in ('fresh','stale','unknown'));

create index if not exists compliance_control_status_freshness_idx
    on public.compliance_control_status (tenant_id, freshness_status, evidence_valid_until);

alter table public.compliance_collection_results
    add column if not exists valid_until timestamptz;

create index if not exists compliance_collection_results_freshness_idx
    on public.compliance_collection_results (tenant_id, valid_until);

-- Append-only evidence remains immutable; only the evaluator may update the
-- current control projection through the existing service role path.
comment on column public.compliance_control_status.evidence_valid_until is
    'Time until which the current automated evaluation may be treated as fresh.';
comment on column public.compliance_collection_results.valid_until is
    'Expiry of this collector result; historical period_end is not freshness.';
