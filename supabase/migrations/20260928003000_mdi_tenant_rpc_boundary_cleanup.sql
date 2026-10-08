begin;

-- MDI tenant-boundary cleanup:
-- remove the legacy non-tenant neighborhood overload and prevent direct client execution
-- of tenant-scoped graph/RAG RPCs. Backend workers use service_role after authentication.
drop function if exists public.mdi_neighborhood(uuid, integer, numeric);

revoke all on function public.mdi_neighborhood(uuid, uuid, integer, numeric) from public, anon, authenticated;
grant execute on function public.mdi_neighborhood(uuid, uuid, integer, numeric) to service_role;

revoke all on function public.mdi_rag_search(uuid, vector, uuid, text[], integer) from public, anon, authenticated;
grant execute on function public.mdi_rag_search(uuid, vector, uuid, text[], integer) to service_role;

commit;
