-- 148_trust_event_visibility_and_worker_observability_v1.sql
begin;
drop policy if exists trust_continuous_verification_member_read on public.trust_continuous_verification_events;
create policy trust_continuous_verification_member_read on public.trust_continuous_verification_events for select to authenticated using (exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_continuous_verification_events.tenant_id and tm.user_id=auth.uid()));
drop policy if exists trust_re_evaluation_events_member_read on public.trust_re_evaluation_events;
create policy trust_re_evaluation_events_member_read on public.trust_re_evaluation_events for select to authenticated using (exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_re_evaluation_events.tenant_id and tm.user_id=auth.uid()));
drop policy if exists trust_re_evaluation_queue_member_read on public.trust_re_evaluation_queue;
create policy trust_re_evaluation_queue_member_read on public.trust_re_evaluation_queue for select to authenticated using (exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_re_evaluation_queue.tenant_id and tm.user_id=auth.uid()));
create or replace function public.trust_re_evaluation_queue_stats() returns jsonb language sql security definer set search_path=public,pg_catalog as $$
 select jsonb_build_object('pending',count(*) filter(where status='PENDING'),'processing',count(*) filter(where status='PROCESSING'),'completed',count(*) filter(where status='COMPLETED'),'failed',count(*) filter(where status='FAILED'),'oldest_pending_at',min(created_at) filter(where status='PENDING'),'failed_last_24h',count(*) filter(where status='FAILED' and coalesce(completed_at,created_at)>=now()-interval '24 hours')) from public.trust_re_evaluation_queue;
$$;
revoke all on function public.trust_re_evaluation_queue_stats() from public,anon,authenticated;
grant execute on function public.trust_re_evaluation_queue_stats() to service_role;
commit;