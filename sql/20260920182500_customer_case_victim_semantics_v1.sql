-- Reconcile customer-case semantics after authorization hardening.
-- A service-request requester is not automatically the incident victim.
-- Keep victim_user_id null unless an explicit verified victim relationship is established.
create or replace function public.open_customer_case(
  p_service_request_id uuid,
  p_operator_user_id uuid,
  p_category text default 'other',
  p_severity text default 'medium'
) returns uuid
language plpgsql security definer
set search_path=public,auth
as $function$
declare
  v_req service_requests%rowtype;
  v_org customer_organizations%rowtype;
  v_case_id uuid;
  v_case_number text;
begin
  if coalesce(auth.role(),'') <> 'service_role' and auth.uid() is distinct from p_operator_user_id then raise exception 'operator_identity_mismatch'; end if;
  if p_operator_user_id is null then raise exception 'operator_required'; end if;
  if coalesce(auth.role(),'') <> 'service_role'
     and not exists (select 1 from workforce.employees e where e.user_id=p_operator_user_id and e.status='active') then raise exception 'operator_not_authorized'; end if;
  if p_category not in ('ransomware','phishing','bec','fraud','sextortion','investment_scam','romance_scam','tech_support','identity_theft','data_breach','extortion','other') then raise exception 'invalid_case_category'; end if;
  if p_severity not in ('low','medium','high','critical') then raise exception 'invalid_case_severity'; end if;
  select * into v_req from service_requests where id=p_service_request_id for update;
  if not found then raise exception 'service_request_not_found'; end if;
  select * into v_org from customer_organizations where id=v_req.organization_id for update;
  if not found or v_org.admission_status <> 'approved' or v_org.tenant_id is null then raise exception 'workspace_not_admitted'; end if;
  if exists(select 1 from customer_case_links where service_request_id=v_req.id) then
    select case_id into v_case_id from customer_case_links where service_request_id=v_req.id;
    return v_case_id;
  end if;
  v_case_id := gen_random_uuid();
  v_case_number := 'CYB-' || to_char(now(),'YYYYMMDD') || '-' || upper(substr(replace(v_case_id::text,'-',''),1,8));
  insert into crime_cases(
    id,tenant_id,case_number,category,severity,status,title,summary,victim_user_id,device_id,
    evidence,ioc_ids,law_enforcement,report_ref,reported_at,financial_loss,currency,wallets,detection_ids
  )
  values(
    v_case_id,v_org.tenant_id,v_case_number,p_category,p_severity,'open',
    'Customer service request: ' || v_req.service_key,v_req.description,null,null,
    '{}'::jsonb,'{}'::uuid[],null,null,now(),null,null,'{}'::text[],'{}'::uuid[]
  );
  insert into customer_case_links(organization_id,service_request_id,case_id,created_by)
  values(v_req.organization_id,v_req.id,v_case_id,p_operator_user_id);
  update service_requests set status='in_progress',updated_at=now() where id=v_req.id;
  insert into customer_case_activity(
    organization_id,case_id,actor_user_id,actor_type,event_type,message,metadata
  )
  values(
    v_req.organization_id,v_case_id,p_operator_user_id,'operator','case_opened',
    'Case opened from customer service request.',
    jsonb_build_object('service_request_id',v_req.id,'service_key',v_req.service_key)
  );
  return v_case_id;
end $function$;
