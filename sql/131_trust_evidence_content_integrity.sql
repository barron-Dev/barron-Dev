-- 131_trust_evidence_content_integrity.sql
-- Content-backed verification: a controlled verifier hashes actual bytes and commits
-- the observed SHA-256 only when it matches the immutable evidence content_hash.

alter table public.trust_evidence
  add column if not exists content_verification_status text not null default 'UNVERIFIED'
    check (content_verification_status in ('UNVERIFIED','VERIFIED','FAILED','EXPIRED','REVOKED')),
  add column if not exists content_verification_method text,
  add column if not exists content_verified_payload_hash text,
  add column if not exists content_verification_hash text,
  add column if not exists content_verified_at timestamptz,
  add column if not exists content_verification_failure_reason text;

create index if not exists idx_trust_evidence_content_verification
  on public.trust_evidence(tenant_id,subject_id,content_verification_status,collected_at desc);

create table if not exists public.trust_evidence_content_verification_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.tenants(id) on delete cascade,
  evidence_id uuid not null references public.trust_evidence(id) on delete restrict,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  verification_status text not null check (verification_status in ('VERIFIED','FAILED','EXPIRED','REVOKED')),
  verifier_type text not null,
  verifier_id text not null,
  verifier_version text,
  verification_method text not null,
  content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
  observed_content_hash text,
  content_uri text,
  verification_hash text not null check (verification_hash ~ '^[0-9a-f]{64}$'),
  reason text,
  verified_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create index if not exists idx_trust_evidence_content_events_evidence
  on public.trust_evidence_content_verification_events(evidence_id,created_at desc);

create or replace function public.trust_evidence_content_verification_events_immutable()
returns trigger language plpgsql set search_path=public,pg_catalog as $$
begin raise exception 'trust_evidence_content_verification_events_are_immutable'; end $$;

drop trigger if exists trust_evidence_content_verification_events_no_update
  on public.trust_evidence_content_verification_events;
create trigger trust_evidence_content_verification_events_no_update
before update or delete on public.trust_evidence_content_verification_events
for each row execute function public.trust_evidence_content_verification_events_immutable();

create or replace function public.trust_evidence_content_verification_hash(
  p_evidence_id uuid,p_subject_id uuid,p_content_hash text,p_observed_content_hash text,
  p_verification_status text,p_verifier_type text,p_verifier_id text,p_verifier_version text,
  p_verification_method text,p_content_uri text,p_verified_at timestamptz,p_reason text)
returns text language sql immutable strict set search_path=public,pg_catalog as $$
select encode(extensions.digest(convert_to(jsonb_build_object(
'evidence_id',p_evidence_id,'subject_id',p_subject_id,'content_hash',p_content_hash,
'observed_content_hash',p_observed_content_hash,'verification_status',p_verification_status,
'verifier_type',p_verifier_type,'verifier_id',p_verifier_id,'verifier_version',p_verifier_version,
'verification_method',p_verification_method,'content_uri',p_content_uri,
'verified_at',p_verified_at,'reason',p_reason)::text,'UTF8'),'sha256'),'hex') $$;

create or replace function public.trust_commit_evidence_content_verification(
  p_evidence_id uuid,p_verification_status text,p_verifier_type text,p_verifier_id text,
  p_verifier_version text,p_verification_method text,p_observed_content_hash text,
  p_verified_at timestamptz,p_reason text)
returns public.trust_evidence_content_verification_events
language plpgsql security definer set search_path=public,pg_catalog as $$
declare e public.trust_evidence;s public.trust_subjects;h text;
ev public.trust_evidence_content_verification_events;
observed text:=lower(trim(coalesce(p_observed_content_hash,'')));
begin
 if p_verification_status not in ('VERIFIED','FAILED','EXPIRED','REVOKED')
 or p_verifier_type is null or p_verifier_id is null or p_verification_method is null
 then raise exception 'invalid_content_verification'; end if;
 select * into e from public.trust_evidence where id=p_evidence_id for share;
 if not found then raise exception 'trust_evidence_not_found'; end if;
 select * into s from public.trust_subjects where id=e.subject_id for share;
 if not found then raise exception 'trust_subject_not_found'; end if;
 if e.tenant_id is distinct from s.tenant_id then raise exception 'trust_evidence_tenant_mismatch'; end if;
 if p_verification_status='VERIFIED' and
   (e.content_hash is null or e.content_hash !~ '^[0-9a-f]{64}$'
    or observed !~ '^[0-9a-f]{64}$' or observed<>e.content_hash)
 then raise exception 'content_hash_mismatch'; end if;
 h:=public.trust_evidence_content_verification_hash(
   e.id,e.subject_id,e.content_hash,case when observed='' then null else observed end,
   p_verification_status,p_verifier_type,p_verifier_id,p_verifier_version,
   p_verification_method,e.content_uri,coalesce(p_verified_at,now()),p_reason);
 insert into public.trust_evidence_content_verification_events(
   tenant_id,evidence_id,subject_id,verification_status,verifier_type,verifier_id,
   verifier_version,verification_method,content_hash,observed_content_hash,
   content_uri,verification_hash,reason,verified_at)
 values(e.tenant_id,e.id,e.subject_id,p_verification_status,p_verifier_type,p_verifier_id,
   p_verifier_version,p_verification_method,e.content_hash,
   case when observed='' then null else observed end,e.content_uri,h,p_reason,coalesce(p_verified_at,now()))
 returning * into ev;
 update public.trust_evidence set
   content_verification_status=p_verification_status,
   content_verification_method=p_verification_method,
   content_verified_payload_hash=case when p_verification_status='VERIFIED' then observed else null end,
   content_verification_hash=h,
   content_verified_at=case when p_verification_status='VERIFIED' then coalesce(p_verified_at,now()) else null end,
   content_verification_failure_reason=case when p_verification_status='VERIFIED' then null else p_reason end
 where id=e.id;
 return ev;
end $$;

revoke all on function public.trust_commit_evidence_content_verification(
 uuid,text,text,text,text,text,text,timestamptz,text) from public,anon,authenticated;
grant execute on function public.trust_commit_evidence_content_verification(
 uuid,text,text,text,text,text,text,timestamptz,text) to service_role;

alter table public.trust_evidence_content_verification_events enable row level security;
drop policy if exists trust_evidence_content_verification_events_member_read
  on public.trust_evidence_content_verification_events;
create policy trust_evidence_content_verification_events_member_read
on public.trust_evidence_content_verification_events for select to authenticated using (
 tenant_id is null or exists (
  select 1 from public.tenant_members tm
  where tm.tenant_id=trust_evidence_content_verification_events.tenant_id
    and tm.user_id=auth.uid()));
revoke all on public.trust_evidence_content_verification_events from anon;
grant select on public.trust_evidence_content_verification_events to authenticated;

create or replace function public.trust_subject_has_content_verified_evidence(
 p_subject_id uuid,p_max_age_seconds integer,p_required_types text[] default null)
returns boolean language sql stable security definer set search_path=public,pg_catalog as $$
select case when p_required_types is null or cardinality(p_required_types)=0 then exists(
 select 1 from public.trust_evidence e where e.subject_id=p_subject_id
 and e.verification_status='VERIFIED' and e.content_verification_status='VERIFIED'
 and e.collected_at>=now()-make_interval(secs=>p_max_age_seconds)
 and(e.expires_at is null or e.expires_at>now()))
else not exists(select 1 from unnest(p_required_types) t(type) where not exists(
 select 1 from public.trust_evidence e where e.subject_id=p_subject_id and e.evidence_type=t.type
 and e.verification_status='VERIFIED' and e.content_verification_status='VERIFIED'
 and e.collected_at>=now()-make_interval(secs=>p_max_age_seconds)
 and(e.expires_at is null or e.expires_at>now()))) end $$;
