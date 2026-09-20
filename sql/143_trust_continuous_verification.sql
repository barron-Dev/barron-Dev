-- Cyclothone Trust v1: continuous verification and certificate lifecycle enforcement.

begin;

create table if not exists public.trust_continuous_verification_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  subject_id uuid not null references public.trust_subjects(id),
  certificate_id uuid null references public.trust_certificates(id),
  previous_state text,
  current_state text,
  previous_state_hash text,
  current_state_hash text,
  action text not null,
  reason text not null,
  verification_result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint trust_continuous_verification_action_chk
    check (action in ('MONITORED','REVERIFY','SUSPENDED','REVOKED','RENEWAL_REQUIRED','NO_ACTIVE_CERTIFICATE'))
);

create index if not exists trust_continuous_verification_subject_idx
 on public.trust_continuous_verification_events(subject_id,created_at desc);
create index if not exists trust_continuous_verification_certificate_idx
 on public.trust_continuous_verification_events(certificate_id,created_at desc);

alter table public.trust_continuous_verification_events enable row level security;
drop policy if exists trust_continuous_verification_member_read on public.trust_continuous_verification_events;
create policy trust_continuous_verification_member_read
 on public.trust_continuous_verification_events for select to authenticated
 using (auth.role()='authenticated');
revoke insert,update,delete on public.trust_continuous_verification_events from anon,authenticated;

create or replace function public.trust_continuous_verify_subject(p_subject_id uuid)
returns jsonb
language plpgsql security definer set search_path=public,'pg_catalog'
as $function$
declare
 s public.trust_subjects; cs public.trust_current_state; c public.trust_certificates;
 old_state text; old_hash text; result jsonb; action_name text; reason_text text;
 verified_count integer:=0; suspended_count integer:=0;
begin
 if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
 select * into s from public.trust_subjects where id=p_subject_id;
 if not found then raise exception 'trust_subject_not_found'; end if;
 select * into cs from public.trust_compute_state(p_subject_id);

 for c in select * from public.trust_certificates
   where subject_id=p_subject_id and status in ('ACTIVE','SUSPENDED')
   order by created_at desc
 loop
   select state,state_hash into old_state,old_hash
     from public.trust_state_snapshots where id=c.state_snapshot_id;

   if c.status='ACTIVE' and (
      old_hash is distinct from cs.state_hash or cs.state not in ('VERIFIED')
      or c.valid_from>now() or c.valid_until<=now()
   ) then
      reason_text := case
        when c.valid_until<=now() then 'certificate_validity_expired'
        when cs.state not in ('VERIFIED') then 'current_trust_state_not_verified'
        else 'current_trust_state_changed'
      end;
      if c.valid_until<=now() then
        perform public.trust_update_certificate_status(c.id,'EXPIRED',reason_text);
        action_name:='RENEWAL_REQUIRED';
      else
        perform public.trust_update_certificate_status(c.id,'SUSPENDED',reason_text);
        action_name:='SUSPENDED'; suspended_count:=suspended_count+1;
      end if;
      insert into public.trust_continuous_verification_events(
        tenant_id,subject_id,certificate_id,previous_state,current_state,
        previous_state_hash,current_state_hash,action,reason,verification_result)
      values(c.tenant_id,p_subject_id,c.id,old_state,cs.state,old_hash,cs.state_hash,
        action_name,reason_text,jsonb_build_object('certificate_id',c.id,'current_assurance',cs.assurance_level));
   elsif c.status='SUSPENDED' then
      result:=public.trust_verify_certificate_chain(c.id);
      insert into public.trust_continuous_verification_events(
        tenant_id,subject_id,certificate_id,previous_state,current_state,
        previous_state_hash,current_state_hash,action,reason,verification_result)
      values(c.tenant_id,p_subject_id,c.id,old_state,cs.state,old_hash,cs.state_hash,
        'REVERIFY','suspended_certificate_rechecked',result);
      verified_count:=verified_count+case when coalesce((result->>'verified')::boolean,false) then 1 else 0 end;
   else
      result:=public.trust_verify_certificate_chain(c.id);
      insert into public.trust_continuous_verification_events(
        tenant_id,subject_id,certificate_id,previous_state,current_state,
        previous_state_hash,current_state_hash,action,reason,verification_result)
      values(c.tenant_id,p_subject_id,c.id,old_state,cs.state,old_hash,cs.state_hash,
        'MONITORED','active_certificate_continuous_check',result);
      verified_count:=verified_count+case when coalesce((result->>'verified')::boolean,false) then 1 else 0 end;
   end if;
 end loop;

 if not exists(select 1 from public.trust_certificates where subject_id=p_subject_id and status='ACTIVE') then
   insert into public.trust_continuous_verification_events(
     tenant_id,subject_id,action,reason,verification_result)
   values(s.tenant_id,p_subject_id,'NO_ACTIVE_CERTIFICATE',
     'subject_has_no_current_active_certificate',
     jsonb_build_object('state',cs.state,'assurance_level',cs.assurance_level));
 end if;

 return jsonb_build_object('subject_id',p_subject_id,'state',cs.state,
   'assurance_level',cs.assurance_level,'state_hash',cs.state_hash,
   'verified_certificates',verified_count,'suspended_certificates',suspended_count);
end;
$function$;

commit;