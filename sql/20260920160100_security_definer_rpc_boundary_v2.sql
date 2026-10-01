revoke all on function public.approve_customer_workspace(uuid,uuid,text) from public,anon,authenticated;
revoke all on function public.reject_customer_workspace(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.approve_customer_workspace(uuid,uuid,text) to service_role;
grant execute on function public.reject_customer_workspace(uuid,uuid,text) to service_role;