-- 120_trust_policy_assurance_profiles.sql
-- Versioned, machine-evaluable Trust policy and assurance requirements.
create table if not exists public.trust_assurance_profiles (
 id uuid primary key default gen_random_uuid(), tenant_id uuid references public.tenants(id) on delete cascade,
 profile_id text not null, version integer not null default 1 check(version>0), display_name text not null, description text,
 min_state text not null default 'VERIFIED' check(min_state in ('REGISTERED','OBSERVED','ATTESTED','VERIFIED','DEGRADED','SUSPENDED','REVOKED','EXPIRED')),
 min_assurance text not null default 'BASIC' check(min_assurance in ('NONE','BASIC','MEASURED','HARDWARE_BACKED','CRYPTOGRAPHIC')),
 max_evidence_age_seconds integer not null default 86400 check(max_evidence_age_seconds between 1 and 31536000),
 max_attestation_age_seconds integer not null default 86400 check(max_attestation_age_seconds between 1 and 31536000),
 require_verified_attestation boolean not null default true, require_measurement boolean not null default true,
 required_evidence_types text[] not null default '{}', allowed_subject_kinds text[] not null default '{}',
 status text not null default 'ACTIVE' check(status in ('ACTIVE','RETIRED')), created_at timestamptz not null default now(),
 unique(tenant_id,profile_id,version)
);
create index if not exists idx_trust_assurance_profiles_active on public.trust_assurance_profiles(tenant_id,status,profile_id);

create table if not exists public.trust_policies (
 id uuid primary key default gen_random_uuid(), tenant_id uuid references public.tenants(id) on delete cascade,
 policy_id text not null, version integer not null default 1 check(version>0), display_name text not null, description text,
 assurance_profile_id uuid not null references public.trust_assurance_profiles(id) on delete restrict,
 certificate_profile_id uuid references public.trust_certificate_profiles(id) on delete restrict,
 decision text not null default 'CERTIFY' check(decision in ('ALLOW','CERTIFY','DENY')),
 status text not null default 'ACTIVE' check(status in ('ACTIVE','RETIRED')),
 rules jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(),
 unique(tenant_id,policy_id,version)
);
create index if not exists idx_trust_policies_active on public.trust_policies(tenant_id,status,policy_id);

create table if not exists public.trust_policy_evaluations (
 id uuid primary key default gen_random_uuid(), tenant_id uuid references public.tenants(id) on delete cascade,
 policy_id uuid not null references public.trust_policies(id) on delete restrict,
 subject_id uuid not null references public.trust_subjects(id) on delete restrict,
 state_snapshot_id uuid references public.trust_state_snapshots(id) on delete restrict,
 decision text not null check(decision in ('ALLOW','CERTIFY','DENY')), assurance text not null,
 evidence_fresh boolean not null, attestation_fresh boolean not null, measurement_present boolean not null,
 required_evidence_present boolean not null, reasons text[] not null default '{}',
 evaluation_hash text not null check(evaluation_hash ~ '^[0-9a-f]{64}$'), evaluated_at timestamptz not null default now()
);
create index if not exists idx_trust_policy_evals_subject on public.trust_policy_evaluations(tenant_id,subject_id,evaluated_at desc);

alter table public.trust_assurance_profiles enable row level security;
alter table public.trust_policies enable row level security;
alter table public.trust_policy_evaluations enable row level security;
drop policy if exists trust_assurance_profiles_member_read on public.trust_assurance_profiles;
create policy trust_assurance_profiles_member_read on public.trust_assurance_profiles for select to authenticated using(tenant_id is null or exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_assurance_profiles.tenant_id and tm.user_id=auth.uid()));
drop policy if exists trust_policies_member_read on public.trust_policies;
create policy trust_policies_member_read on public.trust_policies for select to authenticated using(tenant_id is null or exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_policies.tenant_id and tm.user_id=auth.uid()));
drop policy if exists trust_policy_evals_member_read on public.trust_policy_evaluations;
create policy trust_policy_evals_member_read on public.trust_policy_evaluations for select to authenticated using(tenant_id is null or exists(select 1 from public.tenant_members tm where tm.tenant_id=trust_policy_evaluations.tenant_id and tm.user_id=auth.uid()));

create or replace function public.trust_assurance_rank(v text) returns integer language sql immutable set search_path=public,pg_catalog as $$ select case v when 'NONE' then 0 when 'BASIC' then 1 when 'MEASURED' then 2 when 'HARDWARE_BACKED' then 3 when 'CRYPTOGRAPHIC' then 4 else -1 end $$;
create or replace function public.trust_state_rank(v text) returns integer language sql immutable set search_path=public,pg_catalog as $$ select case v when 'REGISTERED' then 0 when 'OBSERVED' then 1 when 'ATTESTED' then 2 when 'VERIFIED' then 3 when 'DEGRADED' then 1 when 'SUSPENDED' then -1 when 'REVOKED' then -2 when 'EXPIRED' then -2 else -3 end $$;

create or replace function public.trust_evaluate_policy(p_policy_id uuid,p_subject_id uuid)
returns public.trust_policy_evaluations language plpgsql security definer set search_path=public,pg_catalog as $$
declare pol public.trust_policies; ap public.trust_assurance_profiles; s public.trust_subjects; st public.trust_current_state; snap public.trust_state_snapshots; outrow public.trust_policy_evaluations;
 latest_evidence timestamptz; latest_attestation timestamptz; required_ok boolean:=true; measurement_ok boolean:=false; evidence_fresh boolean:=false; attestation_fresh boolean:=false; reasons text[]:='{}'; decision text; req text;
begin
 select * into pol from public.trust_policies where id=p_policy_id and status='ACTIVE'; if not found then raise exception 'trust_policy_not_active'; end if;
 select * into ap from public.trust_assurance_profiles where id=pol.assurance_profile_id and status='ACTIVE' and (tenant_id=pol.tenant_id or tenant_id is null); if not found then raise exception 'trust_assurance_profile_not_active'; end if;
 select * into s from public.trust_subjects where id=p_subject_id and tenant_id=pol.tenant_id; if not found then raise exception 'trust_subject_not_found'; end if;
 select * into st from public.trust_current_state where subject_id=p_subject_id;
 select * into snap from public.trust_state_snapshots where subject_id=p_subject_id order by computed_at desc limit 1;
 if st is null then reasons:=array_append(reasons,'no_current_trust_state'); end if;
 latest_evidence := (select max(collected_at) from public.trust_evidence where subject_id=p_subject_id);
 latest_attestation := (select max(created_at) from public.trust_attestations where subject_id=p_subject_id and status='VERIFIED');
 evidence_fresh := latest_evidence is not null and latest_evidence >= now()-make_interval(secs=>ap.max_evidence_age_seconds);
 attestation_fresh := latest_attestation is not null and latest_attestation >= now()-make_interval(secs=>ap.max_attestation_age_seconds);
 measurement_ok := exists(select 1 from public.trust_measurements where subject_id=p_subject_id and measured_at >= now()-make_interval(secs=>ap.max_evidence_age_seconds));
 foreach req in array ap.required_evidence_types loop
   if not exists(select 1 from public.trust_evidence e where e.subject_id=p_subject_id and e.evidence_type=req and e.collected_at >= now()-make_interval(secs=>ap.max_evidence_age_seconds)) then required_ok:=false; reasons:=array_append(reasons,'missing_evidence:'||req); end if;
 end loop;
 if s.lifecycle_state <> 'ACTIVE' then reasons:=array_append(reasons,'subject_not_active'); end if;
 if st is null or public.trust_state_rank(st.state) < public.trust_state_rank(ap.min_state) then reasons:=array_append(reasons,'state_below_requirement'); end if;
 if st is null or public.trust_assurance_rank(st.assurance_level) < public.trust_assurance_rank(ap.min_assurance) then reasons:=array_append(reasons,'assurance_below_requirement'); end if;
 if ap.require_measurement and not measurement_ok then reasons:=array_append(reasons,'measurement_missing_or_stale'); end if;
 if ap.require_verified_attestation and not attestation_fresh then reasons:=array_append(reasons,'verified_attestation_missing_or_stale'); end if;
 if not evidence_fresh then reasons:=array_append(reasons,'evidence_missing_or_stale'); end if;
 if not required_ok then reasons:=array_append(reasons,'required_evidence_incomplete'); end if;
 if st is not null and st.state='VERIFIED' and s.lifecycle_state='ACTIVE' and evidence_fresh and attestation_fresh and measurement_ok and required_ok and public.trust_assurance_rank(st.assurance_level)>=public.trust_assurance_rank(ap.min_assurance) and public.trust_state_rank(st.state)>=public.trust_state_rank(ap.min_state) then decision:=pol.decision; else decision:='DENY'; end if;
 insert into public.trust_policy_evaluations(tenant_id,policy_id,subject_id,state_snapshot_id,decision,assurance,evidence_fresh,attestation_fresh,measurement_present,required_evidence_present,reasons,evaluation_hash)
 values(pol.tenant_id,pol.id,s.id,snap.id,decision,coalesce(st.assurance_level,'NONE'),evidence_fresh,attestation_fresh,measurement_ok,required_ok,reasons,encode(digest(jsonb_build_object('policy_id',pol.id,'subject_id',s.id,'state',coalesce(st.state,'UNKNOWN'),'assurance',coalesce(st.assurance_level,'NONE'),'evidence_fresh',evidence_fresh,'attestation_fresh',attestation_fresh,'measurement',measurement_ok,'required_evidence',required_ok,'reasons',reasons)::text,'sha256'),'hex')) returning * into outrow;
 return outrow;
end $$;
revoke all on function public.trust_evaluate_policy(uuid,uuid) from public,anon,authenticated;
grant execute on function public.trust_evaluate_policy(uuid,uuid) to service_role;
