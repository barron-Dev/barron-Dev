-- 111_customer_case_service_lifecycle.sql
-- Bridges customer service requests to the existing operational crime_cases system.
-- No duplicate case store and no seed/demo records.

create table if not exists customer_case_links (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  service_request_id uuid not null references service_requests(id) on delete restrict,
  case_id uuid not null references crime_cases(id) on delete cascade,
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now(),
  unique(service_request_id),
  unique(case_id)
);
create index if not exists customer_case_links_org_idx on customer_case_links(organization_id,created_at desc);

create table if not exists customer_case_activity (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  case_id uuid not null references crime_cases(id) on delete cascade,
  actor_user_id uuid references auth.users(id) on delete set null,
  actor_type text not null check(actor_type in ('customer','operator','system')),
  event_type text not null,
  message text not null check(length(trim(message)) between 1 and 5000),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists customer_case_activity_case_idx on customer_case_activity(case_id,created_at desc);

alter table customer_case_links enable row level security;
alter table customer_case_activity enable row level security;

drop policy if exists customer_case_link_member_select on customer_case_links;
create policy customer_case_link_member_select on customer_case_links for select to authenticated
using (exists(select 1 from organization_members m where m.organization_id=customer_case_links.organization_id and m.user_id=(select auth.uid()) and m.status='active'));

drop policy if exists customer_case_activity_member_select on customer_case_activity;
create policy customer_case_activity_member_select on customer_case_activity for select to authenticated
using (exists(select 1 from organization_members m where m.organization_id=customer_case_activity.organization_id and m.user_id=(select auth.uid()) and m.status='active'));

grant select on customer_case_links to authenticated;
grant select on customer_case_activity to authenticated;

create or replace function open_customer_case(
  p_service_request_id uuid,
  p_operator_user_id uuid,
  p_category text default 'other',
  p_severity text default 'medium'
) returns uuid
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_req service_requests%rowtype;
  v_org customer_organizations%rowtype;
  v_case_id uuid;
  v_case_number text;
begin
  if p_operator_user_id is null then raise exception 'operator_required'; end if;
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
    id,tenant_id,case_number,category,severity,status,title,summary,
    victim_user_id,device_id,evidence,ioc_ids,law_enforcement,report_ref,reported_at,
    financial_loss,currency,wallets,detection_ids
  ) values (
    v_case_id,v_org.tenant_id,v_case_number,p_category,p_severity,'open',
    'Customer service request: ' || v_req.service_key,
    v_req.description,v_req.requester_user_id,null,'{}'::jsonb,'{}'::uuid[],
    null,null,now(),null,null,'{}'::text[],'{}'::uuid[]
  );

  insert into customer_case_links(organization_id,service_request_id,case_id,created_by)
  values(v_req.organization_id,v_req.id,v_case_id,p_operator_user_id);

  update service_requests set status='in_progress',updated_at=now() where id=v_req.id;

  insert into customer_case_activity(organization_id,case_id,actor_user_id,actor_type,event_type,message,metadata)
  values(v_req.organization_id,v_case_id,p_operator_user_id,'operator','case_opened',
         'Case opened from customer service request.',
         jsonb_build_object('service_request_id',v_req.id,'service_key',v_req.service_key));

  return v_case_id;
end $$;

revoke all on function open_customer_case(uuid,uuid,text,text) from public;
grant execute on function open_customer_case(uuid,uuid,text,text) to service_role;
