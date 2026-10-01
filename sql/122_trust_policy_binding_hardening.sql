-- 122_trust_policy_binding_hardening.sql
create or replace function public.ai_bind_trust_policy_to_execution_binding(p_binding_id uuid,p_trust_policy_id uuid)
returns public.ai_execution_bindings language plpgsql security definer set search_path=public,pg_catalog as $$
declare b public.ai_execution_bindings; p public.trust_policies%rowtype; outrow public.ai_execution_bindings;
begin
 select * into b from public.ai_execution_bindings where id=p_binding_id for update;
 if not found then raise exception 'execution_binding_not_found'; end if;
 select * into p from public.trust_policies where id=p_trust_policy_id and tenant_id=b.tenant_id and status='ACTIVE';
 if not found then raise exception 'trust_policy_not_active'; end if;
 update public.ai_execution_bindings set trust_policy_id=p.id where id=b.id returning * into outrow; return outrow;
end$$;
revoke all on function public.ai_bind_trust_policy_to_execution_binding(uuid,uuid) from public,anon,authenticated;
grant execute on function public.ai_bind_trust_policy_to_execution_binding(uuid,uuid) to service_role;

create or replace function public.trust_evaluate_policy(p_policy_id uuid,p_subject_id uuid)
returns public.trust_policy_evaluations language plpgsql security definer set search_path=public,pg_catalog as $$
declare pol public.trust_policies; ap public.trust_assurance_profiles; s public.trust_subjects; st public.trust_current_state; snap public.trust_state_snapshots; outrow public.trust_policy_evaluations;
latest_evidence timestamptz; latest_attestation timestamptz; required_ok boolean:=true; measurement_ok boolean:=false; evidence_fresh boolean:=false; attestation_fresh boolean:=false; reasons text[]:='{}'; decision text; req text;
begin
 select * into pol from public.trust_policies where id=p_policy_id and status='ACTIVE'; if not found then raise exception 'trust_policy_not_active'; end if;
 select * into ap from public.trust_assurance_profiles where id=pol.assurance_profile_id and status='ACTIVE' and (tenant_id=pol.tenant_id or tenant_id is null); if not found then raise exception 'trust_assurance_profile_not_active'; end if;
 select * into s from public.trust_subjects where id=p_subject_id and tenant_id=pol.tenant_id; if not found then raise exception 'trust_subject_not_found'; end if;
 select * into st from public.trust_current_state where subject_id=p_subject_id; select * into snap from public.trust_state_snapshots where subject_id=p_subject_id order by computed_at desc limit 1;
 if cardinality(ap.allowed_subject_kinds)>0 and not (s.subject_kind=any(ap.allowed_subject_kinds)) then reasons:=array_append(reasons,'subject_kind_not_allowed'); end if;
 latest_evidence:=(select max(e.collected_at) from public.trust_evidence e where e.subject_id=p_subject_id and (e.expires_at is null or e.expires_at>now()));
 latest_attestation:=(select max(a.verified_at) from public.trust_attestations a where a.subject_id=p_subject_id and a.status='VERIFIED' and a.valid_from<=now() and (a.valid_until is null or a.valid_until>now()));
 evidence_fresh:=latest_evidence is not null and latest_evidence>=now()-make_interval(secs=>ap.max_evidence_age_seconds);
 attestation_fresh:=latest_attestation is not null and latest_attestation>=now()-make_interval(secs=>ap.max_attestation_age_seconds);
 measurement_ok:=exists(select 1 from public.trust_measurements m where m.subject_id=p_subject_id and m.measured_at>=now()-make_interval(secs=>ap.max_evidence_age_seconds));
 foreach req in array ap.required_evidence_types loop
  if not exists(select 1 from public.trust_evidence e where e.subject_id=p_subject_id and e.evidence_type=req and e.collected_at>=now()-make_interval(secs=>ap.max_evidence_age_seconds) and (e.expires_at is null or e.expires_at>now())) then required_ok:=false; reasons:=array_append(reasons,'missing_evidence:'||req); end if;
 end loop;
 if s.lifecycle_state<>'ACTIVE' then reasons:=array_append(reasons,'subject_not_active'); end if;
 if st is null then reasons:=array_append(reasons,'no_current_trust_state'); elsif st.state in('SUSPENDED','REVOKED','EXPIRED') then reasons:=array_append(reasons,'trust_state_blocked'); elsif public.trust_state_rank(st.state)<public.trust_state_rank(ap.min_state) then reasons:=array_append(reasons,'state_below_requirement'); end if;
 if st is null or public.trust_assurance_rank(st.assurance_level)<public.trust_assurance_rank(ap.min_assurance) then reasons:=array_append(reasons,'assurance_below_requirement'); end if;
 if ap.require_measurement and not measurement_ok then reasons:=array_append(reasons,'measurement_missing_or_stale'); end if;
 if ap.require_verified_attestation and not attestation_fresh then reasons:=array_append(reasons,'verified_attestation_missing_or_stale'); end if;
 if not evidence_fresh then reasons:=array_append(reasons,'evidence_missing_or_stale'); end if;
 if not required_ok then reasons:=array_append(reasons,'required_evidence_incomplete'); end if;
 if cardinality(reasons)=0 then decision:=pol.decision; else decision:='DENY'; end if;
 insert into public.trust_policy_evaluations(tenant_id,policy_id,subject_id,state_snapshot_id,decision,assurance,evidence_fresh,attestation_fresh,measurement_present,required_evidence_present,reasons,evaluation_hash)
 values(pol.tenant_id,pol.id,s.id,snap.id,decision,coalesce(st.assurance_level,'NONE'),evidence_fresh,attestation_fresh,measurement_ok,required_ok,reasons,
 encode(extensions.digest(convert_to(jsonb_build_object('policy_id',pol.id,'subject_id',s.id,'state',coalesce(st.state,'UNKNOWN'),'assurance',coalesce(st.assurance_level,'NONE'),'evidence_fresh',evidence_fresh,'attestation_fresh',attestation_fresh,'measurement',measurement_ok,'required_evidence',required_ok,'reasons',reasons)::text,'UTF8'),'sha256'),'hex')) returning * into outrow;
 return outrow;
end$$;
revoke all on function public.trust_evaluate_policy(uuid,uuid) from public,anon,authenticated;
grant execute on function public.trust_evaluate_policy(uuid,uuid) to service_role;
