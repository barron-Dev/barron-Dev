-- 106_customer_admission.sql
-- Controlled workspace admission. No automatic trust, tenant creation, seed, or synthetic records.

alter table customer_organizations
  add column if not exists admission_status text not null default 'pending'
  check (admission_status in ('pending','review','approved','rejected','suspended'));

create table if not exists organization_admissions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  requested_by uuid not null references auth.users(id) on delete restrict,
  status text not null default 'pending'
    check (status in ('pending','review','approved','rejected','suspended')),
  assurance_level text not null default 'registered'
    check (assurance_level in ('registered','domain_verified','business_verified','government_verified','privileged')),
  reviewer_user_id uuid references auth.users(id) on delete set null,
  decision_reason text,
  submitted_at timestamptz not null default now(),
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists organization_admission_active_uq
  on organization_admissions(organization_id)
  where status in ('pending','review');

create table if not exists organization_invitations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  invited_by uuid not null references auth.users(id) on delete restrict,
  email text not null check (length(trim(email)) between 3 and 320),
  role text not null default 'requester'
    check (role in ('owner','admin','security_admin','analyst','developer','requester','viewer')),
  token_hash text not null unique,
  expires_at timestamptz not null,
  accepted_at timestamptz,
  accepted_user_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists organization_invites_org_idx on organization_invitations(organization_id,created_at desc);

alter table organization_admissions enable row level security;
alter table organization_invitations enable row level security;

create policy organization_admission_member_select on organization_admissions
for select to authenticated
using (exists (
  select 1 from organization_members m
  where m.organization_id=organization_admissions.organization_id
    and m.user_id=(select auth.uid()) and m.status='active'
));

create policy organization_admission_owner_insert on organization_admissions
for insert to authenticated
with check (
  requested_by=(select auth.uid())
  and exists (
    select 1 from customer_organizations o
    where o.id=organization_admissions.organization_id
      and o.owner_user_id=(select auth.uid())
  )
);

create policy organization_invitation_admin_select on organization_invitations
for select to authenticated
using (exists (
  select 1 from organization_members m
  where m.organization_id=organization_invitations.organization_id
    and m.user_id=(select auth.uid()) and m.status='active'
    and m.role in ('owner','admin')
));

create policy organization_invitation_admin_insert on organization_invitations
for insert to authenticated
with check (
  invited_by=(select auth.uid())
  and exists (
    select 1 from organization_members m
    where m.organization_id=organization_invitations.organization_id
      and m.user_id=(select auth.uid()) and m.status='active'
      and m.role in ('owner','admin')
  )
);

grant select,insert on organization_admissions to authenticated;
grant select,insert on organization_invitations to authenticated;

create or replace function request_workspace_admission(p_organization_id uuid)
returns uuid
language plpgsql
security invoker
as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;

  if not exists (
    select 1 from customer_organizations
    where id=p_organization_id and owner_user_id=auth.uid()
  ) then
    raise exception 'organization_not_found';
  end if;

  if exists (
    select 1 from organization_admissions
    where organization_id=p_organization_id
      and status in ('pending','review')
  ) then
    raise exception 'admission_already_pending';
  end if;

  insert into organization_admissions(organization_id,requested_by)
  values(p_organization_id,auth.uid())
  returning id into v_id;

  update customer_organizations
  set admission_status='pending', updated_at=now()
  where id=p_organization_id;

  return v_id;
end $$;

grant execute on function request_workspace_admission(uuid) to authenticated;
