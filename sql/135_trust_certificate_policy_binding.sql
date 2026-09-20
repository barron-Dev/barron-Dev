-- 135_trust_certificate_policy_binding.sql
alter table public.trust_certificates add column if not exists trust_policy_id uuid,add column if not exists policy_evaluation_id uuid,add column if not exists policy_version integer,add column if not exists policy_rules_hash text,add column if not exists policy_evaluation_hash text;
create index if not exists idx_trust_cert_policy_binding on public.trust_certificates(tenant_id,trust_policy_id,policy_evaluation_id);
-- Certificate issuance requires an active CERTIFY policy evaluation and records exact policy version/rules/evaluation hashes.
-- The live SECURITY DEFINER function is installed by this migration.