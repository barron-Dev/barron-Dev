-- 110_customer_invitation_acceptance.sql
-- Secure invitation acceptance binds an authenticated account to the invited email.

create or replace function accept_organization_invitation(p_token text)
returns uuid
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_user uuid := auth.uid();
  v_email text := lower(trim(coalesce(auth.jwt()->>'email','')));
  v_hash text;
  v_inv organization_invitations%rowtype;
begin
  if v_user is null then raise exception 'authentication required'; end if;
  if v_email = '' then raise exception 'authenticated_email_required'; end if;
  if p_token is null or length(trim(p_token)) < 20 then raise exception 'invalid_invitation_token'; end if;

  v_hash := encode(extensions.digest(trim(p_token), 'sha256'), 'hex');

  select * into v_inv
  from organization_invitations
  where token_hash=v_hash
  for update;

  if not found then raise exception 'invitation_not_found'; end if;
  if v_inv.accepted_at is not null then raise exception 'invitation_already_accepted'; end if;
  if v_inv.expires_at <= now() then raise exception 'invitation_expired'; end if;
  if lower(trim(v_inv.email)) <> v_email then raise exception 'invitation_email_mismatch'; end if;
  if v_inv.role = 'owner' then raise exception 'invalid_invitation_role'; end if;

  insert into organization_members(organization_id,user_id,role,status)
  values(v_inv.organization_id,v_user,v_inv.role,'active')
  on conflict (organization_id,user_id) do update
    set role=excluded.role,status='active';

  update organization_invitations
  set accepted_at=now(), accepted_user_id=v_user
  where id=v_inv.id;

  return v_inv.organization_id;
end $$;

revoke all on function accept_organization_invitation(text) from public;
grant execute on function accept_organization_invitation(text) to authenticated;
