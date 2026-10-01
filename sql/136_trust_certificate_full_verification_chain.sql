-- 136_trust_certificate_full_verification_chain.sql
alter table public.trust_certificates add column if not exists verification_status text not null default 'UNVERIFIED';
alter table public.trust_certificates add column if not exists verification_hash text;
alter table public.trust_certificates add column if not exists verification_failure_reason text;
alter table public.trust_certificates add column if not exists last_verified_at timestamptz;
create table if not exists public.trust_certificate_verification_events(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,
 certificate_id uuid not null references public.trust_certificates(id) on delete restrict,status text not null,
 verification_hash text not null,reason text,created_at timestamptz not null default now());
alter table public.trust_certificate_verification_events enable row level security;
revoke all on public.trust_certificate_verification_events from public,anon,authenticated;
grant select on public.trust_certificate_verification_events to authenticated;
create policy trust_certificate_verification_events_member_read on public.trust_certificate_verification_events for select to authenticated using(tenant_id is null or exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_certificate_verification_events.tenant_id and tm.user_id=auth.uid()));
-- The live migration installs trust_verify_certificate_chain(), which independently checks certificate→policy→evaluation→proof→attestation bindings and records the result.