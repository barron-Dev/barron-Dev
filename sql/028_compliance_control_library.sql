-- Sentinel Compliance Control Library hardening, migration 028.
-- Extends the existing 027 compliance layer without replacing its tables.
-- This is evidence automation, not legal certification or auditor attestation.

-- The control catalog is globally readable; tenant evidence remains tenant-scoped.
-- The application is service-role-only for writes to these tables.

create or replace function public.compliance_attestation_immutable()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'compliance attestations are append-only';
end;
$$;

drop trigger if exists compliance_attestation_immutable on public.compliance_attestations;
create trigger compliance_attestation_immutable
before update or delete on public.compliance_attestations
for each row execute function public.compliance_attestation_immutable();
revoke all on function public.compliance_attestation_immutable() from public, anon, authenticated;

create or replace function public.compliance_policy_document_immutable()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'compliance policy documents are append-only';
end;
$$;

drop trigger if exists compliance_policy_document_immutable on public.compliance_policy_documents;
create trigger compliance_policy_document_immutable
before update or delete on public.compliance_policy_documents
for each row execute function public.compliance_policy_document_immutable();
revoke all on function public.compliance_policy_document_immutable() from public, anon, authenticated;

-- Store pack signing metadata alongside the existing pack record. The private
-- signing key never enters Postgres.
alter table public.compliance_packs add column if not exists signature text;
alter table public.compliance_packs add column if not exists signer_kid text;

-- Existing 027 checks were intentionally limited to four frameworks. Expand the
-- same tables in-place so existing tenants/runs remain valid.
alter table public.compliance_controls add constraint compliance_controls_framework_fk
    foreign key (framework) references public.compliance_frameworks(id) not valid;

alter table public.compliance_evidence add constraint compliance_evidence_framework_fk
    foreign key (framework) references public.compliance_frameworks(id) not valid;
alter table public.compliance_runs add constraint compliance_runs_framework_fk
    foreign key (framework) references public.compliance_frameworks(id) not valid;
alter table public.compliance_packs add constraint compliance_packs_framework_fk
    foreign key (framework) references public.compliance_frameworks(id) not valid;

-- No direct mutation grants for authenticated users. Existing SELECT policies
-- remain the read boundary; service_role performs writes.
revoke insert, update, delete on public.compliance_controls, public.compliance_evidence,
    public.compliance_runs, public.compliance_packs from anon, authenticated;
revoke insert, update, delete on public.compliance_frameworks, public.compliance_control_status,
    public.compliance_evidence_snapshots, public.compliance_attestations,
    public.compliance_policy_documents from anon, authenticated;
