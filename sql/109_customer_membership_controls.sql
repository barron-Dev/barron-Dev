-- 109_customer_membership_controls.sql
-- Organization membership and invitation controls. No seed/demo records.

create index if not exists organization_members_org_status_idx
  on organization_members(organization_id,status);

create unique index if not exists organization_invitation_active_email_uq
  on organization_invitations(organization_id,lower(email))
  where accepted_at is null and expires_at > now();

create or replace function revoke_organization_invitation(p_invitation_id uuid)
returns void
language plpgsql security invoker
as $$
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;
  if not exists (
    select 1 from organization_invitations i
    join organization_members m on m.organization_id=i.organization_id
    where i.id=p_invitation_id and m.user_id=auth.uid() and m.status='active'
      and m.role in ('owner','admin')
  ) then raise exception 'invitation_not_found'; end if;
  update organization_invitations
  set expires_at=least(expires_at,now()), accepted_at=coalesce(accepted_at,now())
  where id=p_invitation_id and accepted_at is null;
end $$;

grant execute on function revoke_organization_invitation(uuid) to authenticated;
