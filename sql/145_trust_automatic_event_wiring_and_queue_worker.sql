-- 145_trust_automatic_event_wiring_and_queue_worker.sql
-- Cyclothone Trust v1: automatically enqueue authoritative trust changes and
-- provide a bounded service-role queue worker. No synthetic trust state is created.

begin;

alter table public.trust_continuous_verification_events enable row level security;
drop policy if exists trust_continuous_verification_member_read on public.trust_continuous_verification_events;
create policy trust_continuous_verification_member_read on public.trust_continuous_verification_events
for select to authenticated using (
  exists (select 1 from public.tenant_members tm
          where tm.tenant_id=trust_continuous_verification_events.tenant_id
            and tm.user_id=auth.uid())
);
revoke insert,update,delete on public.trust_continuous_verification_events from anon,authenticated;
grant select on public.trust_continuous_verification_events to authenticated;

alter table public.trust_public_key_lifecycle_events enable row level security;
drop policy if exists trust_public_key_lifecycle_events_read on public.trust_public_key_lifecycle_events;
create policy trust_public_key_lifecycle_events_read on public.trust_public_key_lifecycle_events
for select to authenticated using (auth.role()='authenticated');
revoke insert,update,delete on public.trust_public_key_lifecycle_events from anon,authenticated;
grant select on public.trust_public_key_lifecycle_events to authenticated;

create or replace function public.trust_enqueue_re_evaluation_from_source()
returns trigger language plpgsql security definer set search_path=public,pg_catalog
as $function$
declare
 v_subject_id uuid; v_tenant_id uuid; v_event_type text; v_source_id uuid;
 v_source_hash text; v_reason text; v_event_id uuid;
begin
 if tg_table_name='trust_measurements' then
   v_subject_id:=new.subject_id; v_tenant_id:=new.tenant_id; v_source_id:=new.id;
   v_event_type:='MEASUREMENT_RECORDED'; v_reason:='authoritative_measurement_recorded';
   v_source_hash:=case when new.measurement_hash ~ '^[0-9a-f]{64}$' then new.measurement_hash end;
 elsif tg_table_name='trust_evidence' then
   v_subject_id:=new.subject_id; v_tenant_id:=new.tenant_id; v_source_id:=new.id;
   if tg_op='INSERT' then
     v_event_type:='EVIDENCE_RECORDED'; v_reason:='authoritative_evidence_recorded';
   elsif old.verification_status is distinct from new.verification_status and new.verification_status='VERIFIED' then
     v_event_type:='EVIDENCE_VERIFIED'; v_reason:='evidence_cryptographic_verification_changed';
   elsif old.verification_hash is distinct from new.verification_hash and new.verification_hash is not null then
     v_event_type:='EVIDENCE_VERIFIED'; v_reason:='evidence_verification_record_changed';
   elsif old.content_verification_status is distinct from new.content_verification_status and new.content_verification_status='VERIFIED' then
     v_event_type:='EVIDENCE_CONTENT_VERIFIED'; v_reason:='evidence_content_integrity_verified';
   else return new;
   end if;
   v_source_hash:=coalesce(
     case when new.verification_hash ~ '^[0-9a-f]{64}$' then new.verification_hash end,
     case when new.evidence_hash ~ '^[0-9a-f]{64}$' then new.evidence_hash end);
 elsif tg_table_name='trust_attestations' then
   v_subject_id:=new.subject_id; v_tenant_id:=new.tenant_id; v_source_id:=new.id;
   if old.status is distinct from new.status and new.status='VERIFIED' then
     v_event_type:='ATTESTATION_VERIFIED'; v_reason:='authoritative_attestation_verified';
   else return new;
   end if;
   v_source_hash:=case when new.attestation_hash ~ '^[0-9a-f]{64}$' then new.attestation_hash end;
 else return new;
 end if;

 if v_subject_id is null or v_tenant_id is null then raise exception 'trust_source_missing_subject_or_tenant'; end if;

 insert into public.trust_re_evaluation_events(tenant_id,subject_id,event_type,source_id,source_hash,reason)
 values(v_tenant_id,v_subject_id,v_event_type,v_source_id,v_source_hash,v_reason)
 returning id into v_event_id;

 insert into public.trust_re_evaluation_queue(tenant_id,subject_id,event_id,status,available_at)
 values(v_tenant_id,v_subject_id,v_event_id,'PENDING',now())
 on conflict (subject_id) where status in ('PENDING','PROCESSING') do nothing;

 return new;
end;
$function$;

revoke all on function public.trust_enqueue_re_evaluation_from_source() from public,anon,authenticated;

drop trigger if exists trust_measurements_enqueue_reevaluation on public.trust_measurements;
create trigger trust_measurements_enqueue_reevaluation after insert on public.trust_measurements
for each row execute function public.trust_enqueue_re_evaluation_from_source();

drop trigger if exists trust_evidence_enqueue_reevaluation on public.trust_evidence;
create trigger trust_evidence_enqueue_reevaluation
after insert or update of verification_status,verification_hash,content_verification_status on public.trust_evidence
for each row execute function public.trust_enqueue_re_evaluation_from_source();

drop trigger if exists trust_attestations_enqueue_reevaluation on public.trust_attestations;
create trigger trust_attestations_enqueue_reevaluation after update of status on public.trust_attestations
for each row execute function public.trust_enqueue_re_evaluation_from_source();

create or replace function public.trust_process_re_evaluation_queue(p_limit integer default 25)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog
as $function$
declare
 q public.trust_re_evaluation_queue; r jsonb;
 v_processed integer:=0; v_succeeded integer:=0; v_retried integer:=0; v_failed integer:=0;
 v_delay_seconds integer;
begin
 if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
 if p_limit<1 or p_limit>100 then raise exception 'invalid_process_limit'; end if;

 for q in select * from public.trust_claim_re_evaluation(p_limit) loop
   v_processed:=v_processed+1;
   begin
     r:=public.trust_continuous_verify_subject(q.subject_id);
     perform public.trust_complete_re_evaluation(q.id,true,coalesce(r,'{}'::jsonb),null);
     v_succeeded:=v_succeeded+1;
   exception when others then
     v_delay_seconds:=least(3600,greatest(30,(30*power(2,greatest(q.attempts-1,0)))::integer));
     if q.attempts<5 then
       update public.trust_re_evaluation_queue
       set status='PENDING',locked_at=null,
           available_at=now()+make_interval(secs=>v_delay_seconds),
           last_error=left(sqlerrm,2000)
       where id=q.id and status='PROCESSING';
       v_retried:=v_retried+1;
     else
       update public.trust_re_evaluation_queue
       set status='FAILED',locked_at=null,completed_at=null,
           last_error=left(sqlerrm,2000),
           result=jsonb_build_object('terminal_failure',true)
       where id=q.id and status='PROCESSING';
       v_failed:=v_failed+1;
     end if;
   end;
 end loop;

 return jsonb_build_object('processed',v_processed,'succeeded',v_succeeded,'retried',v_retried,'failed',v_failed);
end;
$function$;

revoke all on function public.trust_process_re_evaluation_queue(integer) from public,anon,authenticated;
grant execute on function public.trust_process_re_evaluation_queue(integer) to service_role;

commit;