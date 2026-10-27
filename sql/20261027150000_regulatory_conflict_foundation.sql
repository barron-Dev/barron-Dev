-- Cyclothone regulatory conflict foundation v1.
-- Additive schema only. Does not delete evidence or assert legal precedence.
-- Do not apply to production until isolated migration, RLS, grants, and negative-path tests pass.

begin;

create table if not exists public.evidence_retention_obligations (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete restrict,
    obligation_key text not null check (length(obligation_key) between 1 and 180),
    jurisdiction text not null check (length(jurisdiction) between 2 and 80),
    authority_name text not null check (length(authority_name) between 1 and 240),
    source_citation text not null check (length(source_citation) between 1 and 500),
    source_version text not null check (length(source_version) between 1 and 120),
    source_digest text check (source_digest is null or source_digest ~ '^[0-9a-f]{64}$'),
    evidence_class text not null check (length(evidence_class) between 1 and 160),
    applicability jsonb not null default '{}'::jsonb,
    retention_rule jsonb not null,
    effective_from timestamptz not null,
    effective_until timestamptz,
    legal_reviewed_at timestamptz,
    legal_reviewed_by uuid,
    status text not null default 'unreviewed'
      check (status in ('unreviewed','active','superseded','withdrawn')),
    created_at timestamptz not null default now(),
    created_by uuid,
    constraint evidence_retention_obligations_effective_range
      check (effective_until is null or effective_until > effective_from),
    constraint evidence_retention_obligations_review_gate
      check (status <> 'active' or (legal_reviewed_at is not null and legal_reviewed_by is not null)),
    unique (tenant_id, obligation_key, source_version)
);

create index if not exists evidence_retention_obligations_match_idx
  on public.evidence_retention_obligations (tenant_id, jurisdiction, evidence_class, status, effective_from);

create table if not exists public.evidence_deletion_requests (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete restrict,
    evidence_source text not null check (evidence_source in
      ('compliance_evidence','trust_evidence','investigation_evidence','dw_source_attempts')),
    evidence_record_id uuid not null,
    evidence_sha256 text not null check (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    requester_id uuid not null,
    requester_role text not null,
    legal_basis text not null check (length(legal_basis) between 1 and 160),
    subject_ref text not null check (length(subject_ref) between 1 and 512),
    idempotency_key text not null check (length(idempotency_key) between 16 and 200),
    context_snapshot jsonb not null,
    resolver_version text not null,
    state text not null default 'received'
      check (state in ('received','evidence_verified','obligations_resolved','no_conflict',
        'conflict_detected','applicability_unknown','awaiting_authorized_decision',
        'signature_verified','operation_authorized','operation_verified','blocked','closed')),
    conflict_snapshot jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, idempotency_key),
    unique (tenant_id, id)
);

create index if not exists evidence_deletion_requests_state_idx
  on public.evidence_deletion_requests (tenant_id, state, created_at desc);
create index if not exists evidence_deletion_requests_evidence_idx
  on public.evidence_deletion_requests (tenant_id, evidence_source, evidence_record_id);

create table if not exists public.evidence_deletion_decisions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete restrict,
    request_id uuid not null,
    decision text not null check (decision in
      ('deny','restrict_access','pseudonymize_subject_reference','retain_under_legal_hold',
       'authorize_scoped_deletion','escalate_for_legal_guidance')),
    rationale text not null check (length(rationale) between 1 and 8000),
    obligation_snapshot jsonb not null,
    evidence_snapshot_sha256 text not null check (evidence_snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    dpo_approver_id uuid,
    retention_approver_id uuid,
    dpo_key_id text,
    retention_key_id text,
    dpo_signature text,
    retention_signature text,
    signature_verification jsonb not null default '{}'::jsonb,
    state text not null default 'awaiting_signature_verification'
      check (state in ('awaiting_signature_verification','verified','rejected','superseded')),
    created_at timestamptz not null default now(),
    verified_at timestamptz,
    created_by uuid,
    foreign key (tenant_id, request_id)
      references public.evidence_deletion_requests(tenant_id, id) on delete restrict,
    constraint evidence_deletion_decisions_distinct_approvers
      check (dpo_approver_id is null or retention_approver_id is null or dpo_approver_id <> retention_approver_id),
    constraint evidence_deletion_decisions_verified_requires_signatures
      check (state <> 'verified' or
        (dpo_approver_id is not null and retention_approver_id is not null
         and dpo_key_id is not null and retention_key_id is not null
         and dpo_signature is not null and retention_signature is not null
         and verified_at is not null
         and signature_verification @> '{"verified": true}'::jsonb))
);

create index if not exists evidence_deletion_decisions_request_idx
  on public.evidence_deletion_decisions (tenant_id, request_id, created_at desc);

create table if not exists public.evidence_lifecycle_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete restrict,
    request_id uuid not null,
    event_type text not null check (length(event_type) between 1 and 120),
    event_payload jsonb not null,
    payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
    previous_event_sha256 text check (previous_event_sha256 is null or previous_event_sha256 ~ '^[0-9a-f]{64}$'),
    actor_id uuid,
    occurred_at timestamptz not null default now(),
    foreign key (tenant_id, request_id)
      references public.evidence_deletion_requests(tenant_id, id) on delete restrict
);

create index if not exists evidence_lifecycle_events_request_idx
  on public.evidence_lifecycle_events (tenant_id, request_id, id);

create or replace function public.prevent_evidence_lifecycle_event_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  raise exception 'evidence lifecycle events are append-only';
end;
$$;

drop trigger if exists evidence_lifecycle_events_immutable on public.evidence_lifecycle_events;
create trigger evidence_lifecycle_events_immutable
before update or delete on public.evidence_lifecycle_events
for each row execute function public.prevent_evidence_lifecycle_event_mutation();

alter table public.evidence_retention_obligations enable row level security;
alter table public.evidence_deletion_requests enable row level security;
alter table public.evidence_deletion_decisions enable row level security;
alter table public.evidence_lifecycle_events enable row level security;

revoke all on public.evidence_retention_obligations from anon, authenticated;
revoke all on public.evidence_deletion_requests from anon, authenticated;
revoke all on public.evidence_deletion_decisions from anon, authenticated;
revoke all on public.evidence_lifecycle_events from anon, authenticated;
grant select, insert, update on public.evidence_retention_obligations to service_role;
grant select, insert, update on public.evidence_deletion_requests to service_role;
grant select, insert on public.evidence_deletion_decisions to service_role;
grant select, insert on public.evidence_lifecycle_events to service_role;
revoke update, delete, truncate on public.evidence_lifecycle_events from service_role;

commit;
