begin;

-- Internal trust lifecycle telemetry must never be directly readable by client roles.
-- It has no tenant_id column, so a tenant-safe client policy cannot be expressed.
alter table public.trust_public_key_lifecycle_events enable row level security;
revoke all on public.trust_public_key_lifecycle_events from public, anon, authenticated;
drop policy if exists trust_public_key_lifecycle_events_member_read on public.trust_public_key_lifecycle_events;
drop policy if exists trust_public_key_lifecycle_events_read on public.trust_public_key_lifecycle_events;
drop policy if exists deny_client_trust_public_key_lifecycle_events on public.trust_public_key_lifecycle_events;
create policy deny_client_trust_public_key_lifecycle_events
  on public.trust_public_key_lifecycle_events
  for all
  to anon, authenticated
  using (false)
  with check (false);
grant select on public.trust_public_key_lifecycle_events to service_role;

-- Continuous verification events contain internal trust-state transition evidence.
-- Keep them behind the service-role control plane until a dedicated tenant-scoped
-- read RPC is introduced; never expose the raw event table directly.
alter table public.trust_continuous_verification_events enable row level security;
revoke all on public.trust_continuous_verification_events from public, anon, authenticated;
drop policy if exists trust_continuous_verification_member_read on public.trust_continuous_verification_events;
drop policy if exists deny_client_trust_continuous_verification_events on public.trust_continuous_verification_events;
create policy deny_client_trust_continuous_verification_events
  on public.trust_continuous_verification_events
  for all
  to anon, authenticated
  using (false)
  with check (false);
grant select on public.trust_continuous_verification_events to service_role;

commit;