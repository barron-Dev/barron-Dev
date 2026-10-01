-- Security hardening for privileged PostgreSQL functions.
-- Public/authenticated roles must not be able to invoke secret/key-management functions.
revoke execute on function public.get_vault_secret(text) from public, anon, authenticated;
revoke execute on function public.rotate_signing_key(text, text) from public, anon, authenticated;
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
revoke execute on function public.next_case_number(uuid) from public, anon, authenticated;
revoke execute on function public.set_updated_at() from public, anon, authenticated;
revoke execute on function public.current_tenant_id() from public, anon;
revoke execute on function public.current_tenant_role() from public, anon;
revoke execute on function public.custom_access_token_hook(jsonb) from public, anon, authenticated;

grant execute on function public.current_tenant_id() to authenticated;
grant execute on function public.current_tenant_role() to authenticated;
grant execute on function public.get_vault_secret(text) to service_role;
grant execute on function public.rotate_signing_key(text, text) to service_role;
grant execute on function public.next_case_number(uuid) to service_role;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;
