-- 132_trust_policy_content_integrity.sql
-- Policy/component requirements can require evidence whose bytes were actually
-- hashed by the controlled verifier, not merely signed/recorded.

create or replace function public.trust_evaluate_execution_policy(p_policy_id uuid,p_run_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare
 p public.trust_policies;i public.ai_trust_execution_identities;ap public.trust_assurance_profiles;
 comp text;sid uuid;req jsonb;st public.trust_current_state;s public.trust_subjects;
 min_state text;min_assurance text;max_evidence integer;max_attestation integer;
 require_att boolean;require_meas boolean;require_verified_evidence boolean;
 require_content_verified_evidence boolean;ev timestamptz;at timestamptz;
 meas boolean;ef boolean;af boolean;ve boolean;cv boolean;reasons text[];dec text;h text;
 all_ok boolean:=true;required text[];run_tenant uuid;idx integer;typ text;
begin
 select * into p from public.trust_policies where id=p_policy_id and status='ACTIVE';if not found then raise exception 'trust_policy_not_active';end if;
 select tenant_id into run_tenant from public.ai_runs where id=p_run_id;if run_tenant is null then raise exception 'run_not_found';end if;
 if p.tenant_id is not null and p.tenant_id<>run_tenant then raise exception 'trust_policy_tenant_mismatch';end if;
 select * into i from public.ai_trust_execution_identities where run_id=p_run_id and tenant_id=run_tenant;if not found then raise exception 'execution_identity_not_found';end if;
 select * into ap from public.trust_assurance_profiles where id=p.assurance_profile_id and status='ACTIVE' and(tenant_id=p.tenant_id or tenant_id is null);if not found then raise exception 'trust_assurance_profile_not_active';end if;
 required:=array(select jsonb_array_elements_text(coalesce(p.rules->'required_components','["MODEL"]'::jsonb)));if not('MODEL'=any(required)) then required:=array_append(required,'MODEL');end if;
 foreach comp in array required loop
  sid:=case comp when 'MODEL' then i.model_subject_id when 'AGENT' then i.agent_subject_id when 'TOOL' then i.tool_subject_id when 'PROVIDER' then i.provider_subject_id when 'RUNTIME' then i.runtime_subject_id end;
  reasons:='{}';dec:='ALLOW';req:=coalesce(p.rules->'component_requirements'->comp,'{}'::jsonb);
  min_state:=coalesce(req->>'min_state',ap.min_state);min_assurance:=coalesce(req->>'min_assurance',ap.min_assurance);
  max_evidence:=coalesce((req->>'max_evidence_age_seconds')::integer,ap.max_evidence_age_seconds);
  max_attestation:=coalesce((req->>'max_attestation_age_seconds')::integer,ap.max_attestation_age_seconds);
  require_att:=coalesce((req->>'require_verified_attestation')::boolean,ap.require_verified_attestation);
  require_meas:=coalesce((req->>'require_measurement')::boolean,ap.require_measurement);
  require_verified_evidence:=coalesce((req->>'require_verified_evidence')::boolean,(p.rules->>'require_verified_evidence')::boolean,false);
  require_content_verified_evidence:=coalesce((req->>'require_content_verified_evidence')::boolean,(p.rules->>'require_content_verified_evidence')::boolean,false);
  st:=null;s:=null;ef:=false;af:=false;meas:=false;ve:=true;cv:=true;
  if sid is null then reasons:=array_append(reasons,'component_subject_missing');dec:='DENY';
  else
   select * into s from public.trust_subjects where id=sid and tenant_id=run_tenant;
   if not found then reasons:=array_append(reasons,'component_subject_not_found');dec:='DENY';end if;
   select * into st from public.trust_current_state where subject_id=sid;
   if s.id is not null and s.lifecycle_state<>'ACTIVE' then reasons:=array_append(reasons,'component_subject_not_active');dec:='DENY';end if;
   if st is null then reasons:=array_append(reasons,'no_current_trust_state');dec:='DENY';
   else
    if st.state in('SUSPENDED','REVOKED','EXPIRED') then reasons:=array_append(reasons,'trust_state_blocked');dec:='DENY';end if;
    if public.trust_state_rank(st.state)<public.trust_state_rank(min_state) then reasons:=array_append(reasons,'state_below_requirement');dec:='DENY';end if;
    if public.trust_assurance_rank(st.assurance_level)<public.trust_assurance_rank(min_assurance) then reasons:=array_append(reasons,'assurance_below_requirement');dec:='DENY';end if;
   end if;
   ev:=(select max(e.collected_at) from public.trust_evidence e where e.subject_id=sid and(e.expires_at is null or e.expires_at>now()));
   at:=(select max(a.verified_at) from public.trust_attestations a where a.subject_id=sid and a.status='VERIFIED' and a.valid_from<=now() and(a.valid_until is null or a.valid_until>now()));
   ef:=ev is not null and ev>=now()-make_interval(secs=>max_evidence);af:=at is not null and at>=now()-make_interval(secs=>max_attestation);
   meas:=exists(select 1 from public.trust_measurements m where m.subject_id=sid and m.measured_at>=now()-make_interval(secs=>max_evidence));
   if require_verified_evidence then ve:=public.trust_subject_has_verified_evidence(sid,max_evidence,null);if not ve then reasons:=array_append(reasons,'cryptographically_verified_evidence_missing');dec:='DENY';end if;end if;
   if require_content_verified_evidence then cv:=public.trust_subject_has_content_verified_evidence(sid,max_evidence,null);if not cv then reasons:=array_append(reasons,'content_verified_evidence_missing');dec:='DENY';end if;end if;
   if not ef then reasons:=array_append(reasons,'evidence_missing_or_stale');dec:='DENY';end if;
   if require_att and not af then reasons:=array_append(reasons,'verified_attestation_missing_or_stale');dec:='DENY';end if;
   if require_meas and not meas then reasons:=array_append(reasons,'measurement_missing_or_stale');dec:='DENY';end if;
   for idx in 0..coalesce(jsonb_array_length(req->'required_evidence_types')-1,-1) loop
    typ:=req->'required_evidence_types'->>idx;
    if require_content_verified_evidence then
      if not public.trust_subject_has_content_verified_evidence(sid,max_evidence,array[typ]) then reasons:=array_append(reasons,'missing_content_verified_evidence:'||typ);dec:='DENY';end if;
    elsif not public.trust_subject_has_verified_evidence(sid,max_evidence,array[typ]) then
      reasons:=array_append(reasons,'missing_verified_evidence:'||typ);dec:='DENY';
    end if;
   end loop;
  end if;
  h:=encode(extensions.digest(convert_to(jsonb_build_object('policy_id',p.id,'policy_rules_hash',p.rules_hash,'run_id',p_run_id,'execution_identity_id',i.id,'component_kind',comp,'subject_id',sid,'state',coalesce(st.state,'UNKNOWN'),'assurance',coalesce(st.assurance_level,'NONE'),'evidence_fresh',ef,'attestation_fresh',af,'measurement',meas,'verified_evidence',ve,'content_verified_evidence',cv,'reasons',reasons)::text,'UTF8'),'sha256'),'hex');
  insert into public.trust_execution_component_evaluations(tenant_id,run_id,policy_id,execution_identity_id,component_kind,subject_id,state,assurance,decision,evidence_fresh,attestation_fresh,measurement_present,reasons,evaluation_hash,policy_rules_hash)
  values(run_tenant,p_run_id,p.id,i.id,comp,sid,coalesce(st.state,'UNKNOWN'),coalesce(st.assurance_level,'NONE'),dec,ef,af,meas,reasons,h,p.rules_hash)
  on conflict(run_id,policy_id,component_kind) do update set subject_id=excluded.subject_id,state=excluded.state,assurance=excluded.assurance,decision=excluded.decision,evidence_fresh=excluded.evidence_fresh,attestation_fresh=excluded.attestation_fresh,measurement_present=excluded.measurement_present,reasons=excluded.reasons,evaluation_hash=excluded.evaluation_hash,policy_rules_hash=excluded.policy_rules_hash,evaluated_at=now();
  if dec='DENY' then all_ok:=false;end if;
 end loop;
 return jsonb_build_object('allowed',all_ok,'policy_id',p.id,'policy_rules_hash',p.rules_hash,'run_id',p_run_id,'execution_identity_id',i.id,'components',coalesce((select jsonb_agg(jsonb_build_object('component_kind',c.component_kind,'subject_id',c.subject_id,'decision',c.decision,'state',c.state,'assurance',c.assurance,'reasons',c.reasons,'evaluation_hash',c.evaluation_hash) order by c.component_kind) from public.trust_execution_component_evaluations c where c.run_id=p_run_id and c.policy_id=p.id),'[]'::jsonb));
end $$;

revoke all on function public.trust_evaluate_execution_policy(uuid,uuid) from public,anon,authenticated;
grant execute on function public.trust_evaluate_execution_policy(uuid,uuid) to service_role;
