-- 126_ai_trust_execution_identity_authority.sql
alter table public.ai_trust_execution_decisions add column if not exists execution_identity_id uuid references public.ai_trust_execution_identities(id) on delete restrict;
alter table public.ai_trust_execution_decisions add column if not exists execution_identity_hash text check(execution_identity_hash is null or execution_identity_hash ~ '^[0-9a-f]{64}$');

create or replace function public.ai_trust_execution_decision_hash(p_tenant_id uuid,p_run_id uuid,p_trust_policy_id uuid,p_subject_id uuid,p_policy_evaluation_id uuid,p_decision text,p_reason_code text,p_evaluation_hash text,p_trust_state text,p_assurance_level text,p_execution_identity_hash text default null)
returns text language sql immutable set search_path=public,pg_catalog as $$ select encode(extensions.digest(convert_to(jsonb_build_object('tenant_id',p_tenant_id,'run_id',p_run_id,'trust_policy_id',p_trust_policy_id,'subject_id',p_subject_id,'policy_evaluation_id',p_policy_evaluation_id,'decision',p_decision,'reason_code',p_reason_code,'evaluation_hash',p_evaluation_hash,'trust_state',p_trust_state,'assurance_level',p_assurance_level,'execution_identity_hash',p_execution_identity_hash)::text,'UTF8'),'sha256'),'hex') $$;

create or replace function public.trust_authorize_ai_run(p_run_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare r public.ai_runs; b public.ai_execution_bindings%rowtype; p public.trust_policies%rowtype; s public.trust_subjects%rowtype; e public.trust_policy_evaluations%rowtype; st public.trust_current_state%rowtype; d public.ai_trust_execution_decisions%rowtype; v_policy_id uuid; v_decision text; v_reason text; v_subject_id uuid; v_hash text; v_identity jsonb; v_identity_id uuid; v_identity_hash text;
begin
 select * into r from public.ai_runs where id=p_run_id for update; if not found then raise exception 'run_not_found'; end if;
 v_identity:=public.ai_sync_execution_trust_identity(p_run_id); v_identity_id:=(v_identity->>'execution_identity_id')::uuid; v_identity_hash:=v_identity->>'identity_hash';
 select * into b from public.ai_execution_bindings where tenant_id=r.tenant_id and mission_id=r.mission_id and mission_version=r.mission_version and mission_hash=r.mission_hash and agent_id=r.agent_id and agent_version=r.agent_version and model_id=r.model_id and model_version=r.model_version and provider_id=r.provider_id and provider_binding_version=r.provider_binding_version and coalesce(tool_id,'')=coalesce(r.tool_id,'') and coalesce(tool_version,-1)=coalesce(r.tool_version,-1) and status='ACTIVE' order by created_at desc limit 1;
 v_policy_id:=coalesce(r.trust_policy_id,b.trust_policy_id);
 if v_policy_id is null then return jsonb_build_object('required',false,'allowed',true,'reason_code','TRUST_POLICY_NOT_BOUND','execution_identity_id',v_identity_id,'execution_identity_hash',v_identity_hash); end if;
 select * into p from public.trust_policies where id=v_policy_id and tenant_id=r.tenant_id and status='ACTIVE';
 if not found then v_decision:='DENY'; v_reason:='TRUST_POLICY_NOT_ACTIVE'; else
  v_subject_id:=(v_identity->>'model_subject_id')::uuid; select * into s from public.trust_subjects where id=v_subject_id and tenant_id=r.tenant_id;
  if not found then v_decision:='DENY'; v_reason:='TRUST_SUBJECT_NOT_REGISTERED'; else
   select * into e from public.trust_evaluate_policy(p.id,s.id); select * into st from public.trust_current_state where subject_id=s.id;
   if e.decision in('ALLOW','CERTIFY') then v_decision:='ALLOW'; v_reason:='TRUST_POLICY_ALLOWED'; else v_decision:='DENY'; v_reason:=case when cardinality(e.reasons)>0 then e.reasons[1] else 'TRUST_POLICY_DENIED' end; end if;
  end if;
 end if;
 v_hash:=public.ai_trust_execution_decision_hash(r.tenant_id,r.id,v_policy_id,v_subject_id,case when e.id is null then null else e.id end,v_decision,v_reason,case when e.id is null then null else e.evaluation_hash end,case when st.subject_id is null then null else st.state end,case when st.subject_id is null then null else st.assurance_level end,v_identity_hash);
 insert into public.ai_trust_execution_decisions(tenant_id,run_id,trust_policy_id,subject_id,policy_evaluation_id,decision,reason_code,evaluation_hash,trust_state,assurance_level,decision_hash,execution_identity_id,execution_identity_hash)
 values(r.tenant_id,r.id,v_policy_id,v_subject_id,case when e.id is null then null else e.id end,v_decision,v_reason,case when e.id is null then null else e.evaluation_hash end,case when st.subject_id is null then null else st.state end,case when st.subject_id is null then null else st.assurance_level end,v_hash,v_identity_id,v_identity_hash)
 on conflict(run_id,trust_policy_id) do update set decision=excluded.decision,reason_code=excluded.reason_code,evaluation_hash=excluded.evaluation_hash,policy_evaluation_id=excluded.policy_evaluation_id,trust_state=excluded.trust_state,assurance_level=excluded.assurance_level,decision_hash=excluded.decision_hash,execution_identity_id=excluded.execution_identity_id,execution_identity_hash=excluded.execution_identity_hash,created_at=now()
 returning * into d;
 return jsonb_build_object('required',true,'allowed',d.decision='ALLOW','decision',d.decision,'reason_code',d.reason_code,'trust_policy_id',d.trust_policy_id,'subject_id',d.subject_id,'policy_evaluation_id',d.policy_evaluation_id,'evaluation_hash',d.evaluation_hash,'decision_hash',d.decision_hash,'trust_state',d.trust_state,'assurance_level',d.assurance_level,'execution_identity_id',d.execution_identity_id,'execution_identity_hash',d.execution_identity_hash);
end$$;
revoke all on function public.ai_trust_execution_decision_hash(uuid,uuid,uuid,uuid,uuid,text,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.trust_authorize_ai_run(uuid) from public,anon,authenticated;
grant execute on function public.ai_trust_execution_decision_hash(uuid,uuid,uuid,uuid,uuid,text,text,text,text,text,text) to service_role;
grant execute on function public.trust_authorize_ai_run(uuid) to service_role;