-- 112_customer_case_lifecycle_controls.sql
-- Real lifecycle, assignment, customer/operator activity. No seed/demo records.

create table if not exists customer_case_assignments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  case_id uuid not null references crime_cases(id) on delete cascade,
  operator_user_id uuid not null references auth.users(id) on delete restrict,
  assigned_by uuid not null references auth.users(id) on delete restrict,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  ended_at timestamptz
);
create unique index if not exists customer_case_one_active_assignment
  on customer_case_assignments(case_id) where active;
create index if not exists customer_case_assignments_operator_idx
  on customer_case_assignments(operator_user_id,active,created_at desc);

alter table customer_case_assignments enable row level security;
drop policy if exists customer_case_assignment_member_select on customer_case_assignments;
create policy customer_case_assignment_member_select on customer_case_assignments for select to authenticated
using (exists(select 1 from organization_members m where m.organization_id=customer_case_assignments.organization_id and m.user_id=(select auth.uid()) and m.status='active'));

grant select on customer_case_assignments to authenticated;

create or replace function transition_customer_case(
  p_case_id uuid,
  p_operator_user_id uuid,
  p_status text,
  p_reason text default null
) returns text
language plpgsql security definer
set search_path = public, auth
as $$
declare
  v_case crime_cases%rowtype;
  v_link customer_case_links%rowtype;
  v_old text;
begin
  if p_operator_user_id is null then raise exception 'operator_required'; end if;
  if p_status not in ('open','investigating','contained','closed','reported') then raise exception 'invalid_case_status'; end if;
  select * into v_case from crime_cases where id=p_case_id for update;
  if not found then raise exception 'case_not_found'; end if;
  select * into v_link from customer_case_links where case_id=p_case_id;
  if not found then raise exception 'customer_case_not_found'; end if;
  v_old := v_case.status;
  if v_old = p_status then return p_status; end if;
  update crime_cases set status=p_status,updated_at=now() where id=p_case_id;
  update service_requests
    set status = case when p_status='closed' then 'closed' when p_status='reported' then 'resolved' when p_status in ('investigating','contained') then 'in_progress' else status end,
        updated_at=now()
    where id=v_link.service_request_id;
  insert into customer_case_activity(organization_id,case_id,actor_user_id,actor_type,event_type,message,metadata)
  values(v_link.organization_id,p_case_id,p_operator_user_id,'operator','status_changed',
         coalesce(nullif(trim(p_reason),''),'Case status changed.'),
         jsonb_build_object('from',v_old,'to',p_status,'service_request_id',v_link.service_request_id));
  return p_status;
end $$;

create or replace function add_customer_case_activity(
  p_case_id uuid,
  p_user_id uuid,
  p_message text
) returns uuid
language plpgsql security definer
set search_path = public, auth
as $$
declare
  v_link customer_case_links%rowtype;
  v_id uuid;
begin
  if p_user_id is null then raise exception 'authentication_required'; end if;
  if length(trim(coalesce(p_message,''))) < 1 or length(trim(p_message)) > 5000 then raise exception 'invalid_activity_message'; end if;
  select * into v_link from customer_case_links where case_id=p_case_id;
  if not found then raise exception 'case_not_found'; end if;
  if not exists(select 1 from organization_members where organization_id=v_link.organization_id and user_id=p_user_id and status='active') then
    raise exception 'organization_access_required';
  end if;
  insert into customer_case_activity(organization_id,case_id,actor_user_id,actor_type,event_type,message)
  values(v_link.organization_id,p_case_id,p_user_id,'customer','customer_update',trim(p_message))
  returning id into v_id;
  return v_id;
end $$;

revoke all on function transition_customer_case(uuid,uuid,text,text) from public;
grant execute on function transition_customer_case(uuid,uuid,text,text) to service_role;
revoke all on function add_customer_case_activity(uuid,uuid,text) from public;
grant execute on function add_customer_case_activity(uuid,uuid,text) to service_role;
