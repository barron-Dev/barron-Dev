-- 115_trust_state_engine.sql
-- Deterministic, evidence-derived Trust State. No certificate is implied.
-- State is computed from current immutable measurements/evidence/attestations.

create table if not exists public.trust_state_snapshots (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.trust_subjects(id) on delete cascade,
  state text not null check (state in (
    'UNKNOWN','REGISTERED','OBSERVED','ATTESTED','VERIFIED',
    'DEGRADED','SUSPENDED','REVOKED','EXPIRED'
  )),
  assurance_level text not null check (assurance_level in (
    'NONE','BASIC','MEASURED','HARDWARE_BACKED','CRYPTOGRAPHIC'
  )),
  measurement_count integer not null default 0 check (measurement_count >= 0),
  valid_measurement_count integer not null default 0 check (valid_measurement_count >= 0),
  evidence_count integer not null default 0 check (evidence_count >= 0),
  valid_evidence_count integer not null default 0 check (valid_evidence_count >= 0),
  verified_attestation_count integer not null default 0 check (verified_attestation_count >= 0),
  latest_measurement_at timestamptz,
  latest_evidence_at timestamptz,
  latest_attestation_at timestamptz,
  state_reason text not null,
  state_hash text not null check (state_hash ~ '^[0-9a-f]{64}$'),
  computed_at timestamptz not null default now()
);

create index if not exists idx_trust_state_subject_time
 on public.trust_state_snapshots(subject_id, computed_at desc);

-- Current state is maintained in trust_current_state below; no subquery index is required.
create table if not exists public.trust_current_state (
  subject_id uuid primary key references public.trust_subjects(id) on delete cascade,
  tenant_id uuid references public.tenants(id) on delete cascade,
  state text not null check (state in (
    'UNKNOWN','REGISTERED','OBSERVED','ATTESTED','VERIFIED',
    'DEGRADED','SUSPENDED','REVOKED','EXPIRED'
  )),
  assurance_level text not null check (assurance_level in (
    'NONE','BASIC','MEASURED','HARDWARE_BACKED','CRYPTOGRAPHIC'
  )),
  state_hash text not null check (state_hash ~ '^[0-9a-f]{64}$'),
  reason text not null,
  computed_at timestamptz not null default now()
);

create index if not exists idx_trust_current_state_tenant
 on public.trust_current_state(tenant_id,state);

create or replace function public.trust_compute_state(p_subject_id uuid)
returns public.trust_current_state
language plpgsql
security definer
set search_path=public,pg_catalog
as $$
declare
 s public.trust_subjects;
 r public.trust_current_state;
 m_count integer;
 m_valid integer;
 e_count integer;
 e_valid integer;
 a_count integer;
 latest_m timestamptz;
 latest_e timestamptz;
 latest_a timestamptz;
 new_state text;
 assurance text;
 reason text;
 digest text;
begin
 select * into s from public.trust_subjects where id=p_subject_id;
 if not found then raise exception 'trust_subject_not_found'; end if;

 select count(*)::int,
        count(*) filter (where collected_at <= now() and
          (expires_at is null or expires_at > now()))::int,
        max(collected_at)
 into m_count,m_valid,latest_m
 from public.trust_measurements where subject_id=p_subject_id;

 select count(*)::int,
        count(*) filter (where collected_at <= now() and
          (expires_at is null or expires_at > now()))::int,
        max(collected_at)
 into e_count,e_valid,latest_e
 from public.trust_evidence where subject_id=p_subject_id;

 select count(*) filter (where status='VERIFIED'
          and (valid_until is null or valid_until > now()))::int,
        max(verified_at)
 into a_count,latest_a
 from public.trust_attestations where subject_id=p_subject_id;

 if s.lifecycle_state='REVOKED' then
   new_state:='REVOKED'; assurance:='NONE'; reason:='subject_revoked';
 elsif s.lifecycle_state='EXPIRED' then
   new_state:='EXPIRED'; assurance:='NONE'; reason:='subject_expired';
 elsif s.lifecycle_state='SUSPENDED' then
   new_state:='SUSPENDED'; assurance:='NONE'; reason:='subject_suspended';
 elsif a_count > 0 and m_valid > 0 and e_valid > 0 then
   new_state:='VERIFIED';
   select coalesce(max(assurance_level),'BASIC') into assurance
   from public.trust_attestations
   where subject_id=p_subject_id and status='VERIFIED'
     and (valid_until is null or valid_until > now());
   reason:='current_measurements_and_evidence_support_verified_attestation';
 elsif exists(select 1 from public.trust_attestations where subject_id=p_subject_id and status='VERIFIED')
       and (m_valid=0 or e_valid=0) then
   new_state:='DEGRADED'; assurance:='NONE'; reason:='verified_attestation_lacks_current_evidence';
 elsif exists(select 1 from public.trust_attestations where subject_id=p_subject_id)
       then new_state:='ATTESTED'; assurance:='BASIC'; reason:='attestation_exists_but_is_not_currently_verified';
 elsif e_valid > 0 then
   new_state:='OBSERVED'; assurance:='MEASURED'; reason:='current_evidence_observed';
 elsif m_valid > 0 then
   new_state:='OBSERVED'; assurance:='MEASURED'; reason:='current_measurements_observed';
 elsif m_count > 0 or e_count > 0 then
   new_state:='DEGRADED'; assurance:='NONE'; reason:='only_stale_measurements_or_evidence_available';
 else
   new_state:='REGISTERED'; assurance:='NONE'; reason:='registered_without_current_evidence';
 end if;

 digest:=encode(extensions.digest(convert_to(jsonb_build_object(
   'subject_id',p_subject_id,'state',new_state,'assurance_level',assurance,
   'measurement_count',m_count,'valid_measurement_count',m_valid,
   'evidence_count',e_count,'valid_evidence_count',e_valid,
   'verified_attestation_count',a_count,
   'latest_measurement_at',latest_m,'latest_evidence_at',latest_e,
   'latest_attestation_at',latest_a,'reason',reason
 )::text,'UTF8'),'sha256'),'hex');

 insert into public.trust_state_snapshots(
   tenant_id,subject_id,state,assurance_level,measurement_count,
   valid_measurement_count,evidence_count,valid_evidence_count,
   verified_attestation_count,latest_measurement_at,latest_evidence_at,
   latest_attestation_at,state_reason,state_hash
 ) values(s.tenant_id,p_subject_id,new_state,assurance,m_count,m_valid,e_count,
          e_valid,a_count,latest_m,latest_e,latest_a,reason,digest);

 insert into public.trust_current_state(
   subject_id,tenant_id,state,assurance_level,state_hash,reason
 ) values(p_subject_id,s.tenant_id,new_state,assurance,digest,reason)
 on conflict(subject_id) do update set
   tenant_id=excluded.tenant_id,state=excluded.state,
   assurance_level=excluded.assurance_level,state_hash=excluded.state_hash,
   reason=excluded.reason,computed_at=excluded.computed_at
 returning * into r;
 return r;
end;
$$;

revoke all on function public.trust_compute_state(uuid) from public,anon,authenticated;
grant execute on function public.trust_compute_state(uuid) to service_role;

alter table public.trust_state_snapshots enable row level security;
alter table public.trust_current_state enable row level security;

drop policy if exists trust_state_snapshot_member_read on public.trust_state_snapshots;
create policy trust_state_snapshot_member_read on public.trust_state_snapshots
for select to authenticated using (
 tenant_id is null or exists (
  select 1 from public.tenant_members tm
  where tm.tenant_id=trust_state_snapshots.tenant_id and tm.user_id=auth.uid()
 )
);

drop policy if exists trust_current_state_member_read on public.trust_current_state;
create policy trust_current_state_member_read on public.trust_current_state
for select to authenticated using (
 tenant_id is null or exists (
  select 1 from public.tenant_members tm
  where tm.tenant_id=trust_current_state.tenant_id and tm.user_id=auth.uid()
 )
);

revoke all on public.trust_state_snapshots,public.trust_current_state from anon;
grant select on public.trust_state_snapshots,public.trust_current_state to authenticated;
