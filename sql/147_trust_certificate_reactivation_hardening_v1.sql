-- 147_trust_certificate_reactivation_hardening_v1.sql
begin;
create or replace function public.trust_update_certificate_status(
 p_certificate_id uuid,p_status text,p_reason text default null)
returns public.trust_certificates language plpgsql security definer set search_path=public,pg_catalog
as $$
declare c public.trust_certificates; outrow public.trust_certificates; event_name text;
begin
 if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
 select * into c from public.trust_certificates where id=p_certificate_id;
 if not found then raise exception 'trust_certificate_not_found'; end if;
 if p_status not in ('ACTIVE','SUSPENDED','REVOKED','EXPIRED') then raise exception 'invalid_certificate_status'; end if;
 if c.status='REVOKED' and p_status<>'REVOKED' then raise exception 'revoked_certificate_is_terminal'; end if;
 if c.status='EXPIRED' and p_status='ACTIVE' then raise exception 'expired_certificate_requires_reissue'; end if;
 if c.status='SUSPENDED' and p_status='ACTIVE' then raise exception 'suspended_certificate_requires_recertification'; end if;
 update public.trust_certificates set status=p_status,
 revoked_at=case when p_status='REVOKED' then coalesce(revoked_at,now()) else revoked_at end,
 revocation_reason=case when p_status='REVOKED' then coalesce(p_reason,revocation_reason) else revocation_reason end,
 suspended_at=case when p_status='SUSPENDED' then coalesce(suspended_at,now()) else suspended_at end,
 suspension_reason=case when p_status='SUSPENDED' then coalesce(p_reason,suspension_reason) else suspension_reason end
 where id=p_certificate_id returning * into outrow;
 event_name:=case when p_status='REVOKED' then 'REVOKED' when p_status='SUSPENDED' then 'SUSPENDED' when p_status='ACTIVE' then 'UNSUSPENDED' else 'EXPIRED' end;
 insert into public.trust_certificate_events(tenant_id,certificate_id,event_type,reason,actor_type)
 values(outrow.tenant_id,outrow.id,event_name,p_reason,'SYSTEM');
 return outrow;
end $$;
revoke all on function public.trust_update_certificate_status(uuid,text,text) from public,anon,authenticated;
grant execute on function public.trust_update_certificate_status(uuid,text,text) to service_role;
commit;