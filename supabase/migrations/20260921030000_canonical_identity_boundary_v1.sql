begin;

do $$
begin
  if exists (
    select 1
    from public.customer_organizations
    where admission_status = 'approved'
      and tenant_id is null
  ) then
    raise exception 'canonical_identity_boundary_violation: approved customer organization without tenant';
  end if;
end $$;

comment on table public.tenants is
'Authoritative Cyclothone security/workspace boundary. Tenant identity controls operational authorization, residency, and execution scope.';

comment on table public.customer_organizations is
'Authoritative Cyclothone business/customer identity. tenant_id is the mandatory operational boundary once admitted; this table does not replace tenant identity.';

alter table public.customer_organizations
  add constraint customer_organizations_approved_requires_tenant
  check (admission_status <> 'approved' or tenant_id is not null);

create unique index if not exists customer_organizations_one_workspace_per_tenant
  on public.customer_organizations (tenant_id)
  where tenant_id is not null;

create index if not exists customer_organizations_owner_idx
  on public.customer_organizations (owner_user_id);

create or replace function public.resolve_canonical_identity(
  p_user_id uuid,
  p_tenant_id uuid default null
)
returns table (
  user_id uuid,
  tenant_id uuid,
  tenant_name text,
  tenant_plan text,
  customer_organization_id uuid,
  customer_organization_name text,
  organization_admission_status text,
  identity_status text
)
language sql
stable
security invoker
set search_path = ''
as $$
  select * from (
    select
      p_user_id as user_id,
      t.id as tenant_id,
      t.name as tenant_name,
      t.plan as tenant_plan,
      co.id as customer_organization_id,
      co.legal_name as customer_organization_name,
      co.admission_status as organization_admission_status,
      case
        when co.id is not null and co.admission_status = 'approved' then 'ADMITTED'
        when co.id is not null then 'REGISTERED'
        when t.id is not null then 'TENANT_ONLY'
        else 'UNRESOLVED'
      end as identity_status
    from public.tenants t
    left join public.customer_organizations co on co.tenant_id = t.id
    where t.id = p_tenant_id
      and exists (
        select 1
        from public.tenant_members tm
        where tm.tenant_id = t.id
          and tm.user_id = p_user_id
      )

    union all

    select
      p_user_id,
      co.tenant_id,
      t.name,
      t.plan,
      co.id,
      co.legal_name,
      co.admission_status,
      case
        when co.admission_status = 'approved' and co.tenant_id is not null then 'ADMITTED'
        else 'REGISTERED'
      end
    from public.customer_organizations co
    left join public.tenants t on t.id = co.tenant_id
    where p_tenant_id is null
      and (
        co.owner_user_id = p_user_id
        or exists (
          select 1
          from public.organization_members om
          where om.organization_id = co.id
            and om.user_id = p_user_id
            and om.status = 'active'
        )
      )
  ) q
  order by q.tenant_id nulls last, q.customer_organization_id
$$;

revoke all on function public.resolve_canonical_identity(uuid, uuid) from public;
revoke all on function public.resolve_canonical_identity(uuid, uuid) from anon;
revoke all on function public.resolve_canonical_identity(uuid, uuid) from authenticated;
grant execute on function public.resolve_canonical_identity(uuid, uuid) to service_role;

commit;
