-- trust_reevaluation_worker_hardening
begin;
create or replace function public.trust_complete_re_evaluation(
 p_queue_id uuid,p_success boolean,p_result jsonb default '{}'::jsonb,p_error text default null)
returns public.trust_re_evaluation_queue
language plpgsql security definer set search_path=public,pg_catalog
as $$
declare q public.trust_re_evaluation_queue; v_delay interval;
begin
 if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
 select * into q from public.trust_re_evaluation_queue where id=p_queue_id for update;
 if not found then raise exception 'trust_re_evaluation_job_not_found'; end if;
 if q.status <> 'PROCESSING' then raise exception 'trust_re_evaluation_job_not_processing'; end if;
 if p_success then
   update public.trust_re_evaluation_queue set status='COMPLETED',completed_at=now(),locked_at=null,last_error=null,result=coalesce(p_result,'{}'::jsonb) where id=q.id returning * into q;
 else
   v_delay := least(interval '15 minutes', interval '30 seconds' * power(2::numeric,greatest(q.attempts-1,0)));
   if q.attempts >= 8 then
     update public.trust_re_evaluation_queue set status='FAILED',completed_at=null,locked_at=null,last_error=coalesce(p_error,'reevaluation_failed'),result=coalesce(p_result,'{}'::jsonb) where id=q.id returning * into q;
   else
     update public.trust_re_evaluation_queue set status='PENDING',completed_at=null,locked_at=null,available_at=now()+v_delay,last_error=coalesce(p_error,'reevaluation_failed'),result=coalesce(p_result,'{}'::jsonb) where id=q.id returning * into q;
   end if;
 end if;
 return q;
end $$;
revoke all on function public.trust_complete_re_evaluation(uuid,boolean,jsonb,text) from public,anon,authenticated;
grant execute on function public.trust_complete_re_evaluation(uuid,boolean,jsonb,text) to service_role;
commit;