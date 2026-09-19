-- 105_customer_identity_and_service_requests.sql
-- Customer identity/onboarding foundation. No demo, seed, synthetic, or mock records.
-- Authentication is delegated to Supabase Auth. Organization verification is separate from authentication.
create table if not exists customer_organizations (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete restrict,
  tenant_id uuid references tenants(id) on delete set null,
  organization_type text not null check (organization_type in ('company','government','security_provider','developer','client','partner','individual')),
  legal_name text not null check (length(trim(legal_name)) between 1 and 240),
  country_code text check (country_code is null or country_code ~ '^[A-Z]{2}$'),
  website_domain text,
  registration_number text,
  verification_status text not null default 'pending' check (verification_status in ('pending','domain_verified','business_verified','government_verified','rejected','suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists customer_org_owner_name_uq on customer_organizations(owner_user_id, lower(legal_name));
create index if not exists customer_org_tenant_idx on customer_organizations(tenant_id);

create table if not exists organization_members (
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner' check (role in ('owner','admin','security_admin','analyst','developer','requester','viewer')),
  status text not null default 'active' check (status in ('pending','active','suspended','removed')),
  created_at timestamptz not null default now(),
  primary key (organization_id,user_id)
);
create index if not exists organization_members_user_idx on organization_members(user_id,status);

create table if not exists organization_domains (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  domain text not null check (length(trim(domain)) between 3 and 253),
  verification_token text not null,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  unique(organization_id,lower(domain)),
  unique(lower(domain),verification_token)
);

create table if not exists identity_verifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete cascade,
  subject_user_id uuid references auth.users(id) on delete cascade,
  verification_type text not null check (verification_type in ('email','domain','identity','business','government','authorization')),
  status text not null default 'pending' check (status in ('pending','submitted','under_review','verified','rejected','expired')),
  provider text,
  reference text,
  submitted_at timestamptz,
  verified_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists identity_verifications_org_idx on identity_verifications(organization_id,status);

create table if not exists service_requests (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references customer_organizations(id) on delete restrict,
  requester_user_id uuid not null references auth.users(id) on delete restrict,
  service_key text not null check (service_key in ('cybersecurity_assessment','incident_response','threat_intelligence','brand_protection','dark_web_monitoring','soc_mdr','ai_security','physical_security','compliance','other')),
  urgency text not null default 'normal' check (urgency in ('low','normal','high','critical')),
  description text not null check (length(trim(description)) between 10 and 10000),
  status text not null default 'submitted' check (status in ('submitted','triage','accepted','in_progress','blocked','resolved','closed','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists service_requests_org_idx on service_requests(organization_id,created_at desc);
create index if not exists service_requests_requester_idx on service_requests(requester_user_id,created_at desc);

alter table customer_organizations enable row level security;
alter table organization_members enable row level security;
alter table organization_domains enable row level security;
alter table identity_verifications enable row level security;
alter table service_requests enable row level security;

drop policy if exists customer_org_member_select on customer_organizations;
create policy customer_org_member_select on customer_organizations for select to authenticated
using (exists(select 1 from organization_members m where m.organization_id=id and m.user_id=(select auth.uid()) and m.status='active'));

drop policy if exists customer_org_owner_insert on customer_organizations;
create policy customer_org_owner_insert on customer_organizations for insert to authenticated
with check (owner_user_id=(select auth.uid()));

drop policy if exists customer_org_member_update on customer_organizations;
create policy customer_org_member_update on customer_organizations for update to authenticated
using (exists(select 1 from organization_members m where m.organization_id=id and m.user_id=(select auth.uid()) and m.status='active' and m.role in ('owner','admin')))
with check (owner_user_id=owner_user_id);

drop policy if exists organization_members_self_select on organization_members;
create policy organization_members_self_select on organization_members for select to authenticated
using (user_id=(select auth.uid()) or exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active' and m.role in ('owner','admin')));

drop policy if exists organization_members_owner_insert on organization_members;
create policy organization_members_owner_insert on organization_members for insert to authenticated
with check (user_id=(select auth.uid()) or exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active' and m.role in ('owner','admin')));

drop policy if exists domains_member_access on organization_domains;
create policy domains_member_access on organization_domains for all to authenticated
using (exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active'))
with check (exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active' and m.role in ('owner','admin')));

drop policy if exists verification_member_access on identity_verifications;
create policy verification_member_access on identity_verifications for select to authenticated
using (exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active'));

drop policy if exists service_request_member_access on service_requests;
create policy service_request_member_access on service_requests for select to authenticated
using (exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active'));

drop policy if exists service_request_member_insert on service_requests;
create policy service_request_member_insert on service_requests for insert to authenticated
with check (
  requester_user_id=(select auth.uid())
  and exists(select 1 from organization_members m where m.organization_id=organization_id and m.user_id=(select auth.uid()) and m.status='active' and m.role in ('owner','admin','requester'))
);

grant select,insert,update on customer_organizations to authenticated;
grant select,insert on organization_members to authenticated;
grant select,insert,update,delete on organization_domains to authenticated;
grant select on identity_verifications to authenticated;
grant select,insert on service_requests to authenticated;

create or replace function create_customer_organization(
  p_type text,
  p_legal_name text,
  p_country_code text default null,
  p_domain text default null,
  p_registration_number text default null
) returns uuid
language plpgsql security invoker
as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;
  if p_type not in ('company','government','security_provider','developer','client','partner','individual') then raise exception 'invalid organization type'; end if;
  insert into customer_organizations(owner_user_id,organization_type,legal_name,country_code,website_domain,registration_number)
  values(auth.uid(),p_type,trim(p_legal_name),nullif(upper(trim(p_country_code)),''),nullif(lower(trim(p_domain)),''),nullif(trim(p_registration_number),''))
  returning id into v_id;
  insert into organization_members(organization_id,user_id,role,status) values(v_id,auth.uid(),'owner','active');
  return v_id;
end $$;
grant execute on function create_customer_organization(text,text,text,text,text) to authenticated;
