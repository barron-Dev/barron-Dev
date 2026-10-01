-- 107_customer_workspace_approval.sql
-- Approval decision and tenant provisioning. No seed/operator records.

create table if not exists organization_admission_decisions (
  id uuid primary key default gen_random_uuid(),
  admission_id uuid not null references organization_admissions(id) on delete cascade,
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  decision text not null check (decision in ('approved','rejected','suspended')),
  reviewer_user_id uuid not null references auth.users(id) on delete restrict,
  reason text,
  tenant_id uuid references tenants(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists admission_decisions_org_idx on organization_admission_decisions(organization_id,created_at desc);

alter table organization_admission_decisions enable row level security;
create policy admission_decision_member_select on organization_admission_decisions
for select to authenticated
using (exists (
  select 1 from organization_members m
  where m.organization_id=organization_admission_decisions.organization_id
    and m.user_id=(select auth.uid()) and m.status='active'
));
grant select on organization_admission_decisions to authenticated;

create or replace function approve_customer_workspace(
  p_admission_id uuid,
  p_reviewer uuid,
  p_reason text default null
) returns uuid
language plpgsql
security definer
set search_path=public
as $$
declare
  a organization_admissions%rowtype;
  o customer_organizations%rowtype;
  v_tenant uuid;
  v_slug text;
begin
  select * into a from organization_admissions
  where id=p_admission_id for update;
  if not found then raise exception 'admission_not_found'; end if;
  if a.status not in ('pending','review') then raise exception 'admission_not_actionable'; end if;

  select * into o from customer_organizations where id=a.organization_id for update;
  if not found then raise exception 'organization_not_found'; end if;
  if o.verification_status not in ('domain_verified','business_verified','government_verified') then
    raise exception 'verification_required';
  end if;

  if o.tenant_id is not null then
    v_tenant=o.tenant_id;
  else
    v_slug=regexp_replace(lower(trim(o.legal_name)),'[^a-z0-9]+','-','g');
    v_slug=left(trim(both '-' from v_slug),48)||'-'||substr(replace(o.id::text,'-',''),1,8);
    insert into tenants(name,slug,plan,contract_type,billing_entity)
    values(o.legal_name,v_slug,'essential','standard',o.legal_name)
    returning id into v_tenant;
    insert into tenant_members(tenant_id,user_id,role)
    values(v_tenant,o.owner_user_id,'owner');
    update customer_organizations set tenant_id=v_tenant where id=o.id;
  end if;

  update organization_admissions
  set status='approved',assurance_level=case
    when o.verification_status='government_verified' then 'government_verified'
    when o.verification_status='business_verified' then 'business_verified'
    else 'domain_verified' end,
    reviewer_user_id=p_reviewer,reviewed_at=now(),decision_reason=p_reason,updated_at=now()
  where id=a.id;

  update customer_organizations set admission_status='approved',updated_at=now() where id=o.id;

  insert into organization_admission_decisions(admission_id,organization_id,decision,reviewer_user_id,reason,tenant_id)
  values(a.id,o.id,'approved',p_reviewer,p_reason,v_tenant);

  return v_tenant;
end $$;

create or replace function reject_customer_workspace(
  p_admission_id uuid,
  p_reviewer uuid,
  p_reason text
) returns uuid
language plpgsql
security definer
set search_path=public
as $$
declare v_org uuid;
begin
  select organization_id into v_org from organization_admissions
  where id=p_admission_id and status in ('pending','review') for update;
  if v_org is null then raise exception 'admission_not_actionable'; end if;
  update organization_admissions set status='rejected',reviewer_user_id=p_reviewer,reviewed_at=now(),decision_reason=p_reason,updated_at=now() where id=p_admission_id;
  update customer_organizations set admission_status='rejected',updated_at=now() where id=v_org;
  insert into organization_admission_decisions(admission_id,organization_id,decision,reviewer_user_id,reason)
  values(p_admission_id,v_org,'rejected',p_reviewer,p_reason);
  return v_org;
end $$;

revoke all on function approve_customer_workspace(uuid,uuid,text) from public,authenticated;
revoke all on function reject_customer_workspace(uuid,uuid,text) from public,authenticated;
