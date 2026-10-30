-- CSA Effectiveness Receipt persistence.
-- Candidate migration for PR #101. Do not apply until migration-lineage
-- reconciliation and production migration approval are complete.

create table if not exists public.compliance_effectiveness_receipts (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null,
    assessment_id uuid not null,
    control_id text not null,
    probe_id text not null,
    probe_version text not null,
    scope_digest text not null check (scope_digest ~ '^[0-9a-f]{64}$'),
    input_digest text not null check (input_digest ~ '^[0-9a-f]{64}$'),
    observations jsonb not null check (jsonb_typeof(observations) = 'object'),
    expected_outcome text not null,
    observed_outcome text not null,
    status text not null check (status in ('effective','ineffective','partial','unknown')),
    coverage double precision not null check (coverage >= 0 and coverage <= 1),
    evidence_digest text not null check (evidence_digest ~ '^[0-9a-f]{64}$'),
    signer_key_id text not null,
    signature_b64 text not null,
    receipt_digest text not null unique check (receipt_digest ~ '^[0-9a-f]{64}$'),
    issued_at timestamptz not null,
    created_at timestamptz not null default now()
);

create index if not exists compliance_effectiveness_receipts_tenant_assessment_idx
    on public.compliance_effectiveness_receipts (tenant_id, assessment_id, issued_at desc);
create index if not exists compliance_effectiveness_receipts_tenant_control_idx
    on public.compliance_effectiveness_receipts (tenant_id, control_id, issued_at desc);

alter table public.compliance_effectiveness_receipts enable row level security;
drop policy if exists compliance_effectiveness_receipts_tenant_select
    on public.compliance_effectiveness_receipts;
create policy compliance_effectiveness_receipts_tenant_select
    on public.compliance_effectiveness_receipts
    for select to authenticated
    using (tenant_id = ((auth.jwt() ->> 'tenant_id')::uuid));

revoke all on public.compliance_effectiveness_receipts from public, anon, authenticated;
grant select on public.compliance_effectiveness_receipts to authenticated;
grant select, insert on public.compliance_effectiveness_receipts to service_role;

create or replace function public.reject_compliance_effectiveness_receipt_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'compliance_effectiveness_receipts_are_immutable';
end;
$$;

drop trigger if exists compliance_effectiveness_receipts_immutable
    on public.compliance_effectiveness_receipts;
create trigger compliance_effectiveness_receipts_immutable
    before update or delete on public.compliance_effectiveness_receipts
    for each row execute function public.reject_compliance_effectiveness_receipt_mutation();

comment on table public.compliance_effectiveness_receipts is
    'Append-only, tenant-scoped, Ed25519-signed CSA control-effectiveness receipts. A receipt proves only its declared probe scope.';
