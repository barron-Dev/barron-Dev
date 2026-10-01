-- Compliance signing key RPC must never be reachable through the Data API.
-- The backend uses service_role only.
revoke all on function public.get_signing_key(text) from public, anon, authenticated;
grant execute on function public.get_signing_key(text) to service_role;
