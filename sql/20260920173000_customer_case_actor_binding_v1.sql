-- Bind privileged customer case/workspace actors to the authenticated caller.
-- service_role remains the explicit backend path for server-side workflows.
do $$
declare f record; body text; marker text:=chr(10)||'begin'||chr(10);
begin
  for f in select p.oid,p.proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname in ('open_customer_case','assign_customer_case','transition_customer_case','add_customer_case_activity','approve_customer_workspace','reject_customer_workspace') loop
    body:=pg_get_functiondef(f.oid);
    if f.proname in ('open_customer_case','assign_customer_case','transition_customer_case') then
      body:=replace(body,marker,chr(10)||'begin'||chr(10)||'  if coalesce(auth.role(),'''') <> ''service_role'' and auth.uid() is distinct from p_operator_user_id then raise exception ''operator_identity_mismatch''; end if;'||chr(10));
    elsif f.proname='add_customer_case_activity' then
      body:=replace(body,marker,chr(10)||'begin'||chr(10)||'  if coalesce(auth.role(),'''') <> ''service_role'' and auth.uid() is distinct from p_user_id then raise exception ''actor_identity_mismatch''; end if;'||chr(10));
    else
      body:=replace(body,'begin select organization_id','begin if coalesce(auth.role(),'''') <> ''service_role'' and auth.uid() is distinct from p_reviewer then raise exception ''reviewer_identity_mismatch''; end if; select organization_id');
    end if;
    execute body;
  end loop;
end $$;
