-- AI Security ecosystem evidence registries.
-- Source-only until migration history/source reconciliation is completed.
begin;

create table if not exists public.ai_model_artifact_attestations (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  model_id text not null check (length(model_id) between 1 and 200),
  model_version text not null check (length(model_version) between 1 and 100),
  artifact_sha256 text not null check (artifact_sha256 ~ '^[0-9a-f]{64}$'),
  manifest_sha256 text not null check (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  signer_key_id text not null check (length(signer_key_id) between 1 and 200),
  signature_sha256 text not null check (signature_sha256 ~ '^[0-9a-f]{64}$'),
  runtime text not null check (length(runtime) between 1 and 100),
  runtime_version text not null check (length(runtime_version) between 1 and 100),
  verification_status text not null check (verification_status in ('registered_unverified','verified','rejected','revoked')),
  verification_reason text,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (tenant_id, model_id, model_version, artifact_sha256)
);
create index if not exists ai_model_artifact_attestations_lookup
  on public.ai_model_artifact_attestations (tenant_id, model_id, model_version, created_at desc);
alter table public.ai_model_artifact_attestations enable row level security;
revoke all on public.ai_model_artifact_attestations from public, anon, authenticated;
grant select, insert on public.ai_model_artifact_attestations to service_role;

create table if not exists public.ai_threat_hunt_reviews (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  correlation_id text not null check (length(correlation_id) between 1 and 200),
  evidence_refs jsonb not null check (jsonb_typeof(evidence_refs) = 'array'),
  hypothesis_summaries jsonb not null default '[]'::jsonb check (jsonb_typeof(hypothesis_summaries) = 'array'),
  disposition text not null check (disposition in ('insufficient_evidence','human_review_required','corroborated_for_review')),
  confidence_class text not null check (confidence_class in ('none','limited','contested','corroborated')),
  coverage_gaps jsonb not null default '[]'::jsonb check (jsonb_typeof(coverage_gaps) = 'array'),
  decision_sha256 text not null check (decision_sha256 ~ '^[0-9a-f]{64}$'),
  automatic_enforcement_permitted boolean not null default false check (automatic_enforcement_permitted = false),
  created_at timestamptz not null default now()
);
create index if not exists ai_threat_hunt_reviews_tenant_time
  on public.ai_threat_hunt_reviews (tenant_id, created_at desc);
alter table public.ai_threat_hunt_reviews enable row level security;
revoke all on public.ai_threat_hunt_reviews from public, anon, authenticated;
grant select, insert on public.ai_threat_hunt_reviews to service_role;

create table if not exists public.ai_privacy_proof_verifications (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  circuit_id text not null check (length(circuit_id) between 1 and 200),
  circuit_version text not null check (length(circuit_version) between 1 and 100),
  proof_system text not null check (length(proof_system) between 1 and 100),
  verifier_key_sha256 text not null check (verifier_key_sha256 ~ '^[0-9a-f]{64}$'),
  statement_sha256 text not null check (statement_sha256 ~ '^[0-9a-f]{64}$'),
  proof_sha256 text not null check (proof_sha256 ~ '^[0-9a-f]{64}$'),
  status text not null check (status in ('verified','rejected','unavailable')),
  reason_code text not null check (length(reason_code) between 1 and 120),
  raw_private_data_received boolean not null default false check (raw_private_data_received = false),
  verified_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists ai_privacy_proof_verifications_tenant_time
  on public.ai_privacy_proof_verifications (tenant_id, created_at desc);
alter table public.ai_privacy_proof_verifications enable row level security;
revoke all on public.ai_privacy_proof_verifications from public, anon, authenticated;
grant select, insert on public.ai_privacy_proof_verifications to service_role;

create table if not exists public.ai_interdiction_decisions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete restrict,
  device_id uuid,
  requested_action text not null check (requested_action in ('alert_operator','hold_position','return_to_home','safe_stop','intercept_target','pursue_target','arm','takeoff','goto_location')),
  evidence_refs jsonb not null check (jsonb_typeof(evidence_refs) = 'array'),
  policy_version text not null check (length(policy_version) between 1 and 100),
  requester_id text not null check (length(requester_id) between 1 and 200),
  human_approval_id text,
  decision text not null check (decision in ('deny','approval_recorded_not_dispatched')),
  reason_codes jsonb not null check (jsonb_typeof(reason_codes) = 'array'),
  decision_sha256 text not null check (decision_sha256 ~ '^[0-9a-f]{64}$'),
  dispatch_permitted boolean not null default false check (dispatch_permitted = false),
  created_at timestamptz not null default now()
);
create index if not exists ai_interdiction_decisions_tenant_time
  on public.ai_interdiction_decisions (tenant_id, created_at desc);
alter table public.ai_interdiction_decisions enable row level security;
revoke all on public.ai_interdiction_decisions from public, anon, authenticated;
grant select, insert on public.ai_interdiction_decisions to service_role;

create or replace function public.reject_ai_security_evidence_mutation()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
  raise exception 'ai_security_evidence_is_append_only';
end;
$$;
revoke all on function public.reject_ai_security_evidence_mutation() from public, anon, authenticated;
grant execute on function public.reject_ai_security_evidence_mutation() to service_role;

drop trigger if exists ai_model_artifact_attestations_append_only on public.ai_model_artifact_attestations;
create trigger ai_model_artifact_attestations_append_only before update or delete
  on public.ai_model_artifact_attestations for each row execute function public.reject_ai_security_evidence_mutation();
drop trigger if exists ai_threat_hunt_reviews_append_only on public.ai_threat_hunt_reviews;
create trigger ai_threat_hunt_reviews_append_only before update or delete
  on public.ai_threat_hunt_reviews for each row execute function public.reject_ai_security_evidence_mutation();
drop trigger if exists ai_privacy_proof_verifications_append_only on public.ai_privacy_proof_verifications;
create trigger ai_privacy_proof_verifications_append_only before update or delete
  on public.ai_privacy_proof_verifications for each row execute function public.reject_ai_security_evidence_mutation();
drop trigger if exists ai_interdiction_decisions_append_only on public.ai_interdiction_decisions;
create trigger ai_interdiction_decisions_append_only before update or delete
  on public.ai_interdiction_decisions for each row execute function public.reject_ai_security_evidence_mutation();

commit;
