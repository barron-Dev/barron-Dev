-- Security hardening follow-up: remove membership helper from exposed public schema.
begin;
create or replace function private.security_is_org_member(p_org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $function$
 select exists (
  select 1 from public.organization_members m
  where m.organization_id = p_org_id
    and m.user_id = auth.uid()
    and m.status = 'active'
 );
$function$;
revoke all on function private.security_is_org_member(uuid) from public, anon;
grant execute on function private.security_is_org_member(uuid) to authenticated, service_role;

drop policy if exists security_targets_select on public.security_targets;
create policy security_targets_select on public.security_targets for select to authenticated
 using (private.security_is_org_member(organization_id));
drop policy if exists security_targets_insert on public.security_targets;
create policy security_targets_insert on public.security_targets for insert to authenticated
 with check (private.security_is_org_member(organization_id));
drop policy if exists security_targets_update on public.security_targets;
create policy security_targets_update on public.security_targets for update to authenticated
 using (private.security_is_org_member(organization_id))
 with check (private.security_is_org_member(organization_id));
drop policy if exists security_claims_select on public.security_claims;
create policy security_claims_select on public.security_claims for select to authenticated
 using (private.security_is_org_member(organization_id));
drop policy if exists security_claim_history_select on public.security_claim_history;
create policy security_claim_history_select on public.security_claim_history for select to authenticated
 using (private.security_is_org_member(organization_id));
drop policy if exists security_claim_requests_select on public.security_claim_requests;
create policy security_claim_requests_select on public.security_claim_requests for select to authenticated
 using (exists (
  select 1 from public.security_claims c
  where c.id = claim_id and private.security_is_org_member(c.organization_id)
 ));
drop function if exists public.security_is_org_member(uuid);
commit;
