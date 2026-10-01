-- 108_customer_service_admission_gate.sql
drop policy if exists service_request_member_insert on service_requests;
create policy service_request_member_insert on service_requests for insert to authenticated with check(
 requester_user_id=(select auth.uid()) and exists(
  select 1 from organization_members m join customer_organizations o on o.id=m.organization_id
  where m.organization_id=service_requests.organization_id and m.user_id=(select auth.uid())
    and m.status='active' and m.role in ('owner','admin','requester')
    and o.admission_status='approved' and o.tenant_id is not null
 )
);
