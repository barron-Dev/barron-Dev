-- Harden AI execution transaction ordering:
-- 1) envelope replay claim occurs before authorization/commit;
-- 2) destructive approval is consumed before commit, with transaction rollback
--    preserving the approval if any later step fails.

create or replace function public.ai_authorize_and_commit_execution(
 p_run_id uuid,p_agent_id uuid,p_mission_id text,p_model_id text,p_provider_id text,p_tool_id text,
 p_risk_level text,p_destructive boolean,p_estimated_cost_usd numeric,p_execution_config jsonb,
 p_agent_version integer,p_mission_version integer,p_mission_hash text,p_model_version integer,
 p_provider_binding_version integer,p_tool_version integer,p_approval_ref text default null,
 p_policy_version text default null,p_policy_hash text default null,p_playbook_version text default null,
 p_playbook_hash text default null,p_twin_version text default null,p_twin_hash text default null,
 p_envelope_id text default null,p_envelope_hash text default null,p_actor text default 'system',
 p_lease_seconds integer default 600,p_action_hash text default null)
returns jsonb language plpgsql security definer set search_path='public','pg_catalog'
as $function$
declare v_trust jsonb; v_auth jsonb; v_commit jsonb; v_admission_hash text;
begin
 if p_execution_config is null then raise exception 'execution_config_required'; end if;
 if p_destructive then
   if p_approval_ref is null or p_action_hash is null or p_action_hash !~ '^[0-9a-f]{64}$' then
     raise exception 'destructive_execution_approval_context_required';
   end if;
   perform public.ai_consume_execution_approval(p_run_id,p_approval_ref,p_action_hash,p_risk_level);
 end if;
 v_trust:=public.trust_authorize_ai_run(p_run_id);
 if coalesce((v_trust->>'allowed')::boolean,false) is not true then
   return v_trust||jsonb_build_object('execution_blocked',true);
 end if;
 v_auth:=public.ai_authorize_execution(
   p_run_id,p_agent_id,p_mission_id,p_model_id,p_provider_id,p_tool_id,p_risk_level,
   p_destructive,p_estimated_cost_usd,p_approval_ref,p_policy_version,p_policy_hash,
   p_actor,p_lease_seconds,p_action_hash);
 if coalesce((v_auth->>'allowed')::boolean,false) is not true then return v_auth; end if;
 v_admission_hash:=public.ai_execution_admission_hash(p_run_id);
 v_commit:=public.ai_execution_commit(
   p_run_id,(v_auth->>'decision_id')::bigint,p_execution_config,p_agent_version,
   p_mission_id,p_mission_version,p_mission_hash,p_model_id,p_model_version,p_provider_id,
   p_provider_binding_version,p_tool_id,p_tool_version,p_policy_version,p_policy_hash,
   p_playbook_version,p_playbook_hash,p_twin_version,p_twin_hash,p_envelope_id,p_envelope_hash,
   v_admission_hash);
 return v_commit||jsonb_build_object(
   'allowed',true,'decision','ALLOW','decision_id',v_auth->>'decision_id',
   'decision_hash',v_auth->>'decision_hash','admission_hash',v_admission_hash,'trust',v_trust);
end$function$;

create or replace function public.ai_execute_run(
 p_run_id uuid,p_risk_level text,p_destructive boolean,p_estimated_cost_usd numeric,
 p_execution_config jsonb,p_approval_ref text default null,p_action_hash text default null,
 p_actor text default 'system',p_lease_seconds integer default 600,p_envelope_id text default null,
 p_envelope_hash text default null,p_envelope_expires_at timestamptz default null)
returns jsonb language plpgsql security definer set search_path='public','pg_catalog'
as $function$
declare r public.ai_runs; v_result jsonb; v_claimed boolean;
begin
 select * into r from public.ai_runs where id=p_run_id for update;
 if not found then raise exception 'run_not_found'; end if;
 if p_envelope_id is not null then
   if p_envelope_hash is null or p_envelope_expires_at is null then
     raise exception 'envelope_replay_context_required';
   end if;
   v_claimed:=public.claim_ai_execution_envelope(
     r.tenant_id,p_envelope_id,p_envelope_hash,p_envelope_expires_at,r.id);
   if not v_claimed then raise exception 'execution_envelope_replay_rejected'; end if;
 end if;
 v_result:=public.ai_authorize_and_commit_execution(
   r.id,r.agent_id,r.mission_id,r.model_id,r.provider_id,r.tool_id,p_risk_level,p_destructive,
   p_estimated_cost_usd,p_execution_config,r.agent_version,r.mission_version,r.mission_hash,
   r.model_version,r.provider_binding_version,r.tool_version,p_approval_ref,r.policy_version,
   r.policy_hash,r.playbook_version,r.playbook_hash,r.twin_version,r.twin_hash,p_envelope_id,
   p_envelope_hash,left(p_actor,128),p_lease_seconds,p_action_hash);
 return v_result;
end;
$function$;

revoke all on function public.ai_authorize_and_commit_execution(uuid,uuid,text,text,text,text,text,boolean,numeric,jsonb,integer,integer,text,integer,integer,integer,text,text,text,text,text,text,text,text,text,text,integer,text) from public,anon,authenticated;
grant execute on function public.ai_authorize_and_commit_execution(uuid,uuid,text,text,text,text,text,boolean,numeric,jsonb,integer,integer,text,integer,integer,integer,text,text,text,text,text,text,text,text,text,text,integer,text) to service_role;
revoke all on function public.ai_execute_run(uuid,text,boolean,numeric,jsonb,text,text,text,integer,text,text,timestamptz) from public,anon,authenticated;
grant execute on function public.ai_execute_run(uuid,text,boolean,numeric,jsonb,text,text,text,integer,text,text,timestamptz) to service_role;