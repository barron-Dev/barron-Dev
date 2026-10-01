-- Sentinel Compliance security hardening.
-- Trigger-only SECURITY DEFINER function must never be callable through the API.
revoke all on function public.compliance_immutable_guard() from public, anon, authenticated;
grant execute on function public.compliance_immutable_guard() to service_role;
