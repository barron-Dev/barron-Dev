-- Pin function search paths to reduce search-path hijacking risk.
alter function public.current_tenant_id() set search_path = pg_catalog, auth, public;
alter function public.current_tenant_role() set search_path = pg_catalog, auth, public;
alter function public.custom_access_token_hook(jsonb) set search_path = pg_catalog, public;
alter function public.set_updated_at() set search_path = pg_catalog;
alter function public.next_case_number(uuid) set search_path = pg_catalog, public;
