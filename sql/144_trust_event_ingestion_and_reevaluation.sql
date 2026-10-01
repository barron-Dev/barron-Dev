-- 144_trust_event_ingestion_and_reevaluation.sql
-- Cyclothone Trust v1: append-only trust events + idempotent re-evaluation queue.
-- No synthetic trust state is created. Events only cause re-evaluation of real subjects.

begin;

create table if not exists public.trust_re_evaluation_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  event_type text not null,
  source_id uuid,
  source_hash text,
  reason text not null,
  created_at timestamptz not null default now(),
  constraint trust_re_evaluation_event_type_chk check (
    event_type in (
      'MEASUREMENT_RECORDED',
      'EVIDENCE_RECORDED',
      'EVIDENCE_VERIFIED',
      'EVIDENCE_CONTENT_VERIFIED',
      'ATTESTATION_VERIFIED',
      'STATE_REEVALUATION_REQUESTED'
    )
  ),
  constraint trust_re_evaluation_source_hash_chk
    check (source_hash is null or source_hash ~ '^[0-9a-f]{64}$')
);

create index if not exists trust_re_evaluation_events_subject_idx
  on public.trust_re_evaluation_events(subject_id, created_at desc);

create index if not exists trust_re_evaluation_events_created_idx
  on public.trust_re_evaluation_events(created_at);

create table if not exists public.trust_re_evaluation_queue (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  event_id uuid not null references public.trust_re_evaluation_events(id) on delete restrict,
  status text not null default 'PENDING'
    check (status in ('PENDING','PROCESSING','COMPLETED','FAILED')),
  attempts integer not null default 0 check (attempts >= 0),
  available_at timestamptz not null default now(),
  locked_at timestamptz,
  completed_at timestamptz,
  last_error text,
  result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists trust_re_evaluation_queue_pending_idx
  on public.trust_re_evaluation_queue(status, available_at, created_at)
  where status in ('PENDING','PROCESSING');

-- One pending/processing job per subject prevents event storms from causing
-- concurrent trust-state races. Completed jobs remain immutable history.
create unique index if not exists trust_re_evaluation_queue_subject_open_uq
  on public.trust_re_evaluation_queue(subject_id)
  where status in ('PENDING','PROCESSING');

alter table public.trust_re_evaluation_events enable row level security;
alter table public.trust_re_evaluation_queue enable row level security;

drop policy if exists trust_re_evaluation_events_member_read
  on public.trust_re_evaluation_events;
create policy trust_re_evaluation_events_member_read
  on public.trust_re_evaluation_events for select to authenticated
  using (
    exists (
      select 1 from public.tenant_members tm
      where tm.tenant_id=trust_re_evaluation_events.tenant_id
        and tm.user_id=auth.uid()
    )
  );

drop policy if exists trust_re_evaluation_queue_member_read
  on public.trust_re_evaluation_queue;
create policy trust_re_evaluation_queue_member_read
  on public.trust_re_evaluation_queue for select to authenticated
  using (
    exists (
      select 1 from public.tenant_members tm
      where tm.tenant_id=trust_re_evaluation_queue.tenant_id
        and tm.user_id=auth.uid()
    )
  );

revoke insert,update,delete on public.trust_re_evaluation_events
  from anon,authenticated;
revoke insert,update,delete on public.trust_re_evaluation_queue
  from anon,authenticated;
grant select on public.trust_re_evaluation_events to authenticated;
grant select on public.trust_re_evaluation_queue to authenticated;

create or replace function public.trust_enqueue_re_evaluation(
  p_subject_id uuid,
  p_event_type text,
  p_source_id uuid default null,
  p_source_hash text default null,
  p_reason text default 'trust_input_changed'
)
returns uuid
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
declare
  s public.trust_subjects;
  v_event_id uuid;
  v_queue_id uuid;
begin
  if auth.role() <> 'service_role' then
    raise exception 'service_role_required';
  end if;

  if p_event_type not in (
    'MEASUREMENT_RECORDED','EVIDENCE_RECORDED','EVIDENCE_VERIFIED',
    'EVIDENCE_CONTENT_VERIFIED','ATTESTATION_VERIFIED',
    'STATE_REEVALUATION_REQUESTED'
  ) then
    raise exception 'invalid_trust_re_evaluation_event_type';
  end if;

  if p_source_hash is not null and p_source_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid_source_hash';
  end if;

  select * into s
  from public.trust_subjects
  where id=p_subject_id;

  if not found then
    raise exception 'trust_subject_not_found';
  end if;

  insert into public.trust_re_evaluation_events(
    tenant_id,subject_id,event_type,source_id,source_hash,reason
  ) values (
    s.tenant_id,p_subject_id,p_event_type,p_source_id,p_source_hash,
    coalesce(nullif(trim(p_reason),''),'trust_input_changed')
  )
  returning id into v_event_id;

  -- If a job is already open, the new immutable event is still recorded but
  -- does not create a second concurrent job. The next worker run recomputes
  -- the entire subject state from authoritative tables.
  insert into public.trust_re_evaluation_queue(
    tenant_id,subject_id,event_id,status,available_at
  ) values (
    s.tenant_id,p_subject_id,v_event_id,'PENDING',now()
  )
  on conflict (subject_id) where status in ('PENDING','PROCESSING')
  do nothing
  returning id into v_queue_id;

  return coalesce(v_queue_id,v_event_id);
end;
$function$;

revoke all on function public.trust_enqueue_re_evaluation(uuid,text,uuid,text,text)
  from public,anon,authenticated;
grant execute on function public.trust_enqueue_re_evaluation(uuid,text,uuid,text,text)
  to service_role;

-- Worker claim is atomic and service-role only. A stale PROCESSING job can be
-- reclaimed after 5 minutes; this avoids permanently stuck trust subjects.
create or replace function public.trust_claim_re_evaluation(
  p_limit integer default 25
)
returns setof public.trust_re_evaluation_queue
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
begin
  if auth.role() <> 'service_role' then
    raise exception 'service_role_required';
  end if;

  if p_limit < 1 or p_limit > 100 then
    raise exception 'invalid_claim_limit';
  end if;

  update public.trust_re_evaluation_queue
     set status='PENDING', locked_at=null,
         last_error=coalesce(last_error,'stale_processing_reclaimed')
   where status='PROCESSING'
     and locked_at < now()-interval '5 minutes';

  return query
  with claimed as (
    select q.id
    from public.trust_re_evaluation_queue q
    where q.status='PENDING'
      and q.available_at<=now()
    order by q.created_at
    for update skip locked
    limit p_limit
  )
  update public.trust_re_evaluation_queue q
     set status='PROCESSING',attempts=q.attempts+1,locked_at=now()
    from claimed c
   where q.id=c.id
  returning q.*;
end;
$function$;

revoke all on function public.trust_claim_re_evaluation(integer)
  from public,anon,authenticated;
grant execute on function public.trust_claim_re_evaluation(integer)
  to service_role;

create or replace function public.trust_complete_re_evaluation(
  p_queue_id uuid,
  p_success boolean,
  p_result jsonb default '{}'::jsonb,
  p_error text default null
)
returns public.trust_re_evaluation_queue
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
declare q public.trust_re_evaluation_queue;
begin
  if auth.role() <> 'service_role' then
    raise exception 'service_role_required';
  end if;

  select * into q
  from public.trust_re_evaluation_queue
  where id=p_queue_id
  for update;

  if not found then
    raise exception 'trust_re_evaluation_job_not_found';
  end if;

  if q.status <> 'PROCESSING' then
    raise exception 'trust_re_evaluation_job_not_processing';
  end if;

  update public.trust_re_evaluation_queue
     set status=case when p_success then 'COMPLETED' else 'FAILED' end,
         completed_at=case when p_success then now() else null end,
         locked_at=null,
         last_error=case when p_success then null else coalesce(p_error,'reevaluation_failed') end,
         result=coalesce(p_result,'{}'::jsonb)
   where id=q.id
   returning * into q;

  return q;
end;
$function$;

revoke all on function public.trust_complete_re_evaluation(uuid,boolean,jsonb,text)
  from public,anon,authenticated;
grant execute on function public.trust_complete_re_evaluation(uuid,boolean,jsonb,text)
  to service_role;

-- Suspended certificates may not be silently promoted to ACTIVE. Reactivation
-- must happen through a future explicit, evidence-backed re-certification path.
create or replace function public.trust_block_suspended_certificate_reactivation()
returns trigger
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
begin
  if old.status='SUSPENDED' and new.status='ACTIVE' then
    raise exception 'suspended_certificate_reactivation_requires_recertification';
  end if;
  return new;
end;
$function$;

drop trigger if exists trust_certificates_block_suspended_reactivation
  on public.trust_certificates;
create trigger trust_certificates_block_suspended_reactivation
before update on public.trust_certificates
for each row execute function public.trust_block_suspended_certificate_reactivation();

commit;
