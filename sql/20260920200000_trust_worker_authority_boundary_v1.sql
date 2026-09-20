-- Trust cryptographic/control-plane hardening.
-- 1) Authority verification must resolve TRUST_AUTHORITY keys, matching issuance.
-- 2) Service-only workers must use current_user rather than deprecated auth.role().
-- No production trust data is created by this migration.

create or replace function public.trust_verify_certificate_authority_binding(p_certificate_id uuid)
returns jsonb
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare c public.trust_certificates%rowtype; k public.trust_public_key_directory%rowtype; reasons text[]:='{}'; v_hash text;
begin
 if current_user<>'service_role' then raise exception 'service_role_required'; end if;
 select * into c from public.trust_certificates where id=p_certificate_id;
 if not found then return jsonb_build_object('verified',false,'reasons',jsonb_build_array('certificate_not_found')); end if;
 if c.authority_key_id is null or c.authority_signature is null or c.authority_signed_payload_hash is null then
   reasons:=array_append(reasons,'certificate_authority_endorsement_missing');
 else
   select * into k from public.trust_public_key_directory where key_id=c.authority_key_id and purpose='TRUST_AUTHORITY';
   if not found then reasons:=array_append(reasons,'certificate_authority_key_not_found');
   else
     if k.algorithm<>'ED25519' then reasons:=array_append(reasons,'certificate_authority_key_invalid'); end if;
     if k.status='REVOKED' then reasons:=array_append(reasons,'certificate_authority_key_revoked'); end if;
     if k.not_before is not null and k.not_before>c.issued_at then reasons:=array_append(reasons,'certificate_authority_key_before_issuance'); end if;
     if k.not_after is not null and k.not_after<=c.valid_until then reasons:=array_append(reasons,'certificate_authority_key_before_certificate_expiry'); end if;
     if c.authority_signed_payload_hash<>c.payload_hash then reasons:=array_append(reasons,'certificate_authority_payload_mismatch'); end if;
   end if;
 end if;
 v_hash:=encode(extensions.digest(convert_to(jsonb_build_object('certificate_id',c.id,'authority_key_id',c.authority_key_id,'authority_signed_payload_hash',c.authority_signed_payload_hash,'reasons',reasons)::text,'utf8'),'sha256'),'hex');
 return jsonb_build_object('verified',array_length(reasons,1) is null,'reasons',to_jsonb(reasons),'verification_hash',v_hash,'authority_key_id',c.authority_key_id,'authority_signed_payload_hash',c.authority_signed_payload_hash);
end $$;

create or replace function public.trust_continuous_verify_subject(p_subject_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog
as $$
declare s public.trust_subjects; cs public.trust_current_state; c public.trust_certificates; old_state text; old_hash text; result jsonb; action_name text; reason_text text; verified_count integer:=0; suspended_count integer:=0;
begin
 if current_user<>'service_role' then raise exception 'service_role_required'; end if;
 select * into s from public.trust_subjects where id=p_subject_id;
 if not found then raise exception 'trust_subject_not_found'; end if;
 select * into cs from public.trust_compute_state(p_subject_id);
 for c in select * from public.trust_certificates where subject_id=p_subject_id and status in ('ACTIVE','SUSPENDED') order by created_at desc loop
   old_state:=null; old_hash:=null; select state,state_hash into old_state,old_hash from public.trust_state_snapshots where id=c.state_snapshot_id;
   if c.status='ACTIVE' and (old_hash is distinct from cs.state_hash or cs.state not in ('VERIFIED') or c.valid_from>now() or c.valid_until<=now()) then
     reason_text:=case when c.valid_until<=now() then 'certificate_validity_expired' when cs.state not in ('VERIFIED') then 'current_trust_state_not_verified' else 'current_trust_state_changed' end;
     if c.valid_until<=now() then perform public.trust_update_certificate_status(c.id,'EXPIRED',reason_text); action_name:='RENEWAL_REQUIRED';
     else perform public.trust_update_certificate_status(c.id,'SUSPENDED',reason_text); action_name:='SUSPENDED'; suspended_count:=suspended_count+1; end if;
     insert into public.trust_continuous_verification_events(tenant_id,subject_id,certificate_id,previous_state,current_state,previous_state_hash,current_state_hash,action,reason,verification_result)
     values(c.tenant_id,p_subject_id,c.id,old_state,cs.state,old_hash,cs.state_hash,action_name,reason_text,jsonb_build_object('certificate_id',c.id,'current_assurance',cs.assurance_level));
   elsif c.status='SUSPENDED' then
     result:=public.trust_verify_certificate_chain(c.id);
     insert into public.trust_continuous_verification_events(tenant_id,subject_id,certificate_id,previous_state,current_state,previous_state_hash,current_state_hash,action,reason,verification_result)
     values(c.tenant_id,p_subject_id,c.id,old_state,cs.state,old_hash,cs.state_hash,'REVERIFY','suspended_certificate_rechecked',result);
     verified_count:=verified_count+case when coalesce((result->>'verified')::boolean,false) then 1 else 0 end;
   else
     result:=public.trust_verify_certificate_chain(c.id);
     insert into public.trust_continuous_verification_events(tenant_id,subject_id,certificate_id,previous_state,current_state,previous_state_hash,current_state_hash,action,reason,verification_result)
     values(c.tenant_id,p_subject_id,c.id,old_state,cs.state,old_hash,cs.state_hash,'MONITORED','active_certificate_continuous_check',result);
     verified_count:=verified_count+case when coalesce((result->>'verified')::boolean,false) then 1 else 0 end;
   end if;
 end loop;
 if not exists(select 1 from public.trust_certificates where subject_id=p_subject_id and status='ACTIVE') then
   insert into public.trust_continuous_verification_events(tenant_id,subject_id,action,reason,verification_result)
   values(s.tenant_id,p_subject_id,'NO_ACTIVE_CERTIFICATE','subject_has_no_current_active_certificate',jsonb_build_object('state',cs.state,'assurance_level',cs.assurance_level));
 end if;
 return jsonb_build_object('subject_id',p_subject_id,'state',cs.state,'assurance_level',cs.assurance_level,'state_hash',cs.state_hash,'verified_certificates',verified_count,'suspended_certificates',suspended_count);
end $$;

create or replace function public.trust_process_re_evaluation_queue(p_limit integer default 25)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog
as $$
declare q public.trust_re_evaluation_queue; r jsonb; v_processed integer:=0; v_succeeded integer:=0; v_retried integer:=0; v_failed integer:=0; v_delay_seconds integer;
begin
 if current_user<>'service_role' then raise exception 'service_role_required'; end if;
 if p_limit<1 or p_limit>100 then raise exception 'invalid_process_limit'; end if;
 for q in select * from public.trust_claim_re_evaluation(p_limit) loop
  v_processed:=v_processed+1;
  begin
   r:=public.trust_continuous_verify_subject(q.subject_id);
   perform public.trust_complete_re_evaluation(q.id,true,coalesce(r,'{}'::jsonb),null); v_succeeded:=v_succeeded+1;
  exception when others then
   v_delay_seconds:=least(3600,greatest(30,(30*power(2,greatest(q.attempts-1,0)))::integer));
   if q.attempts<5 then
    update public.trust_re_evaluation_queue set status='PENDING',locked_at=null,available_at=now()+make_interval(secs=>v_delay_seconds),last_error=left(sqlerrm,2000) where id=q.id and status='PROCESSING'; v_retried:=v_retried+1;
   else
    update public.trust_re_evaluation_queue set status='FAILED',locked_at=null,completed_at=null,last_error=left(sqlerrm,2000),result=jsonb_build_object('terminal_failure',true) where id=q.id and status='PROCESSING'; v_failed:=v_failed+1;
   end if;
  end;
 end loop;
 return jsonb_build_object('processed',v_processed,'succeeded',v_succeeded,'retried',v_retried,'failed',v_failed);
end $$;
