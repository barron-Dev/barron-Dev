-- 121_ai_trust_execution_boundary.sql
alter table public.ai_execution_bindings add column if not exists trust_policy_id uuid references public.trust_policies(id) on delete restrict;
alter table public.ai_runs add column if not exists trust_policy_id uuid references public.trust_policies(id) on delete restrict;
create index if not exists idx_ai_execution_bindings_trust_policy on public.ai_execution_bindings(tenant_id,trust_policy_id,status) where trust_policy_id is not null;
create index if not exists idx_ai_runs_trust_policy on public.ai_runs(tenant_id,trust_policy_id) where trust_policy_id is not null;

create table if not exists public.ai_trust_execution_decisions(
 id bigint generated always as identity primary key, tenant_id uuid not null references public.tenants(id) on delete cascade,
 run_id uuid not null references public.ai_runs(id) on delete restrict, trust_policy_id uuid not null references public.trust_policies(id) on delete restrict,
 subject_id uuid references public.trust_subjects(id) on delete restrict, policy_evaluation_id uuid references public.trust_policy_evaluations(id) on delete restrict,
 decision text not null check(decision in('ALLOW','DENY')), reason_code text not null, evaluation_hash text, trust_state text, assurance_level text,
 decision_hash text not null check(decision_hash ~ '^[0-9a-f]{64}$'), created_at timestamptz not null default now()
);
create unique index if not exists uq_ai_trust_execution_decision on public.ai_trust_execution_decisions(run_id,trust_policy_id);
alter table public.ai_trust_execution_decisions enable row level security;
revoke all on public.ai_trust_execution_decisions from public,anon,authenticated;

create or replace function public.ai_trust_execution_decision_hash(p_tenant_id uuid,p_run_id uuid,p_trust_policy_id uuid,p_subject_id uuid,p_policy_evaluation_id uuid,p_decision text,p_reason_code text,p_evaluation_hash text,p_trust_state text,p_assurance_level text)
returns text language sql immutable set search_path=public,pg_catalog as $$
select encode(extensions.digest(convert_to(jsonb_build_object('tenant_id',p_tenant_id,'run_id',p_run_id,'trust_policy_id',p_trust_policy_id,'subject_id',p_subject_id,'policy_evaluation_id',p_policy_evaluation_id,'decision',p_decision,'reason_code',p_reason_code,'evaluation_hash',p_evaluation_hash,'trust_state',p_trust_state,'assurance_level',p_assurance_level)::text,'UTF8'),'sha256'),'hex')$$;

create or replace function public.trust_authorize_ai_run(p_run_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare r public.ai_runs; b public.ai_execution_bindings%rowtype; p public.trust_policies%rowtype; s public.trust_subjects%rowtype;
e public.trust_policy_evaluations%rowtype; st public.trust_current_state%rowtype; d public.ai_trust_execution_decisions%rowtype;
v_policy_id uuid; v_decision text; v_reason text; v_subject_id uuid; v_hash text;
begin
select * into r from public.ai_runs where id=p_run_id for update; if not found then raise exception 'run_not_found'; end if;
select * into b from public.ai_execution_bindings where tenant_id=r.tenant_id and mission_id=r.mission_id and mission_version=r.mission_version and mission_hash=r.mission_hash and agent_id=r.agent_id and agent_version=r.agent_version and model_id=r.model_id and model_version=r.model_version and provider_id=r.provider_id and provider_binding_version=r.provider_binding_version and tool_id=r.tool_id and tool_version=r.tool_version and status='ACTIVE' order by created_at desc limit 1;
v_policy_id:=coalesce(r.trust_policy_id,b.trust_policy_id);
if v_policy_id is null then return jsonb_build_object('required',false,'allowed',true,'reason_code','TRUST_POLICY_NOT_BOUND'); end if;
select * into p from public.trust_policies where id=v_policy_id and tenant_id=r.tenant_id and status='ACTIVE';
if not found then v_decision:='DENY'; v_reason:='TRUST_POLICY_NOT_ACTIVE';
else
select * into s from public.trust_subjects where tenant_id=r.tenant_id and subject_kind='MODEL_VERSION' and (external_ref=r.model_id||':'||r.model_version::text or external_ref=r.model_id) order by case when external_ref=r.model_id||':'||r.model_version::text then 0 else 1 end,created_at desc limit 1;
if not found then select * into s from public.trust_subjects where tenant_id=r.tenant_id and subject_kind='MODEL' and external_ref=r.model_id order by created_at desc limit 1; end if;
if not found then v_decision:='DENY'; v_reason:='TRUST_SUBJECT_NOT_REGISTERED';
else v_subject_id:=s.id; select * into e from public.trust_evaluate_policy(p.id,s.id); select * into st from public.trust_current_state where subject_id=s.id;
if e.decision in('ALLOW','CERTIFY') then v_decision:='ALLOW'; v_reason:='TRUST_POLICY_ALLOWED'; else v_decision:='DENY'; v_reason:=case when cardinality(e.reasons)>0 then e.reasons[1] else 'TRUST_POLICY_DENIED' end; end if; end if; end if;
v_hash:=public.ai_trust_execution_decision_hash(r.tenant_id,r.id,v_policy_id,v_subject_id,case when e.id is null then null else e.id end,v_decision,v_reason,case when e.id is null then null else e.evaluation_hash end,case when st.subject_id is null then null else st.state end,case when st.subject_id is null then null else st.assurance_level end);
insert into public.ai_trust_execution_decisions(tenant_id,run_id,trust_policy_id,subject_id,policy_evaluation_id,decision,reason_code,evaluation_hash,trust_state,assurance_level,decision_hash)
values(r.tenant_id,r.id,v_policy_id,v_subject_id,case when e.id is null then null else e.id end,v_decision,v_reason,case when e.id is null then null else e.evaluation_hash end,case when st.subject_id is null then null else st.state end,case when st.subject_id is null then null else st.assurance_level end,v_hash)
on conflict(run_id,trust_policy_id) do update set decision=excluded.decision,reason_code=excluded.reason_code,evaluation_hash=excluded.evaluation_hash,policy_evaluation_id=excluded.policy_evaluation_id,trust_state=excluded.trust_state,assurance_level=excluded.assurance_level,decision_hash=excluded.decision_hash,created_at=now()
returning * into d;
return jsonb_build_object('required',true,'allowed',d.decision='ALLOW','decision',d.decision,'reason_code',d.reason_code,'trust_policy_id',d.trust_policy_id,'subject_id',d.subject_id,'policy_evaluation_id',d.policy_evaluation_id,'evaluation_hash',d.evaluation_hash,'decision_hash',d.decision_hash,'trust_state',d.trust_state,'assurance_level',d.assurance_level);
end$$;

revoke all on function public.ai_trust_execution_decision_hash(uuid,uuid,uuid,uuid,uuid,text,text,text,text,text) from public,anon,authenticated;
revoke all on function public.trust_authorize_ai_run(uuid) from public,anon,authenticated;
grant execute on function public.ai_trust_execution_decision_hash(uuid,uuid,uuid,uuid,uuid,text,text,text,text,text) to service_role;
grant execute on function public.trust_authorize_ai_run(uuid) to service_role;

create or replace function public.ai_authorize_and_commit_execution(
 p_run_id uuid,p_agent_id uuid,p_mission_id text,p_model_id text,p_provider_id text,p_tool_id text,p_risk_level text,p_destructive boolean,p_estimated_cost_usd numeric(18,8),p_execution_config jsonb,p_agent_version integer,p_mission_version integer,p_mission_hash text,p_model_version integer,p_provider_binding_version integer,p_tool_version integer,p_approval_ref text default null,p_policy_version text default null,p_policy_hash text default null,p_playbook_version text default null,p_playbook_hash text default null,p_twin_version text default null,p_twin_hash text default null,p_envelope_id text default null,p_envelope_hash text default null,p_actor text default 'system',p_lease_seconds integer default 600,p_action_hash text default null)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare v_trust jsonb; v_auth jsonb; v_commit jsonb; v_admission_hash text;
begin
if p_execution_config is null then raise exception 'execution_config_required'; end if;
v_trust:=public.trust_authorize_ai_run(p_run_id);
if coalesce((v_trust->>'allowed')::boolean,false) is not true then return v_trust||jsonb_build_object('execution_blocked',true); end if;
v_auth:=public.ai_authorize_execution(p_run_id,p_agent_id,p_mission_id,p_model_id,p_provider_id,p_tool_id,p_risk_level,p_destructive,p_estimated_cost_usd,p_approval_ref,p_policy_version,p_policy_hash,p_actor,p_lease_seconds,p_action_hash);
if coalesce((v_auth->>'allowed')::boolean,false) is not true then return v_auth; end if;
v_admission_hash:=public.ai_execution_admission_hash(p_run_id);
v_commit:=public.ai_execution_commit(p_run_id,(v_auth->>'decision_id')::bigint,p_execution_config,p_agent_version,p_mission_id,p_mission_version,p_mission_hash,p_model_id,p_model_version,p_provider_id,p_provider_binding_version,p_tool_id,p_tool_version,p_policy_version,p_policy_hash,p_playbook_version,p_playbook_hash,p_twin_version,p_twin_hash,p_envelope_id,p_envelope_hash,v_admission_hash);
if p_destructive then if p_approval_ref is null or p_action_hash is null then raise exception 'destructive_execution_approval_context_required'; end if; perform public.ai_consume_execution_approval(p_run_id,p_approval_ref,p_action_hash,p_risk_level); end if;
return v_commit||jsonb_build_object('allowed',true,'decision','ALLOW','decision_id',v_auth->>'decision_id','decision_hash',v_auth->>'decision_hash','admission_hash',v_admission_hash,'trust',v_trust);
end$$;

revoke all on function public.ai_authorize_and_commit_execution(uuid,uuid,text,text,text,text,text,boolean,numeric(18,8),jsonb,integer,integer,text,integer,integer,integer,text,text,text,text,text,text,text,text,text,text,integer,text) from public,anon,authenticated;
grant execute on function public.ai_authorize_and_commit_execution(uuid,uuid,text,text,text,text,text,boolean,numeric(18,8),jsonb,integer,integer,text,integer,integer,integer,text,text,text,text,text,text,text,text,text,text,integer,text) to service_role;
