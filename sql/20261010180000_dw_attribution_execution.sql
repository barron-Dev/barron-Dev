-- Complete the internal attribution execution path. This migration is additive and must
-- be applied only through the approved release workflow; committing it changes no DB.
alter table public.dw_actor_profiles add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
alter table public.dw_actor_profiles add column if not exists review_status text not null default 'pending' check (review_status in ('pending','accepted','rejected','needs_more_evidence'));
create index if not exists dw_actor_profiles_tenant_idx on public.dw_actor_profiles(tenant_id, last_activity desc);

alter table public.dw_attribution_assessments add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
alter table public.dw_attribution_assessments add column if not exists review_status text not null default 'pending' check (review_status in ('pending','accepted','rejected','needs_more_evidence'));
alter table public.dw_attribution_assessments add column if not exists reviewed_by uuid references auth.users(id) on delete set null;
alter table public.dw_attribution_assessments add column if not exists reviewed_at timestamptz;
alter table public.dw_attribution_assessments add column if not exists review_notes text;
create index if not exists dw_attribution_tenant_idx on public.dw_attribution_assessments(tenant_id, created_at desc);
create unique index if not exists dw_attribution_tenant_cluster_uidx on public.dw_attribution_assessments(tenant_id, activity_cluster_id);

alter table public.dw_actor_evidence add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
create index if not exists dw_actor_evidence_tenant_idx on public.dw_actor_evidence(tenant_id, created_at desc);

create table if not exists public.dw_actor_attribution_jobs (
  job_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  watchlist_id uuid not null references public.dw_watchlist(id) on delete cascade,
  status text not null default 'queued' check (status in ('queued','running','done','failed')),
  attempts integer not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  locked_at timestamptz,
  last_error_code text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists dw_actor_attribution_active_job_uidx
  on public.dw_actor_attribution_jobs(tenant_id, watchlist_id) where status in ('queued','running');
create index if not exists dw_actor_attribution_jobs_due_idx on public.dw_actor_attribution_jobs(status, next_attempt_at);

create table if not exists public.dw_attribution_alert_outbox (
  alert_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  assessment_id uuid references public.dw_attribution_assessments(assessment_id) on delete set null,
  event_type text not null check (event_type in ('PROVISIONAL_ACTOR_CREATED','ATTRIBUTION_TIER_CHANGED','PROFILE_CHANGED')),
  payload jsonb not null,
  created_at timestamptz not null default now(),
  dispatched_at timestamptz,
  attempts integer not null default 0,
  last_error_code text
);
create index if not exists dw_attribution_alert_pending_idx on public.dw_attribution_alert_outbox(created_at) where dispatched_at is null;

create table if not exists public.dw_attribution_webhooks (
  webhook_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  endpoint_url text not null,
  secret_ciphertext text not null,
  event_types text[] not null default array['PROVISIONAL_ACTOR_CREATED','ATTRIBUTION_TIER_CHANGED','PROFILE_CHANGED'],
  enabled boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  last_delivery_at timestamptz
);
create index if not exists dw_attribution_webhooks_tenant_idx on public.dw_attribution_webhooks(tenant_id, enabled);

create table if not exists public.dw_attribution_webhook_deliveries (
  delivery_id uuid primary key default gen_random_uuid(),
  alert_id uuid not null references public.dw_attribution_alert_outbox(alert_id) on delete cascade,
  webhook_id uuid not null references public.dw_attribution_webhooks(webhook_id) on delete cascade,
  status text not null check (status in ('delivered','retryable_failure','permanent_failure')),
  http_status integer,
  error_code text,
  attempts integer not null default 1,
  created_at timestamptz not null default now(),
  unique(alert_id, webhook_id)
);

alter table public.dw_actor_attribution_jobs enable row level security;
alter table public.dw_attribution_alert_outbox enable row level security;
alter table public.dw_attribution_webhooks enable row level security;
alter table public.dw_attribution_webhook_deliveries enable row level security;
revoke all on public.dw_actor_attribution_jobs, public.dw_attribution_alert_outbox, public.dw_attribution_webhooks, public.dw_attribution_webhook_deliveries from anon, authenticated;
grant select, insert, update, delete on public.dw_actor_attribution_jobs, public.dw_attribution_alert_outbox, public.dw_attribution_webhooks, public.dw_attribution_webhook_deliveries to service_role;

create or replace function public.enqueue_dw_attribution_job(p_tenant_id uuid, p_watchlist_id uuid)
returns uuid language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_job uuid;
begin
  if p_tenant_id is null or p_watchlist_id is null then raise exception 'tenant_and_watch_required'; end if;
  if not exists(select 1 from public.dw_watchlist w where w.id=p_watchlist_id and w.tenant_id=p_tenant_id) then
    raise exception 'watchlist_tenant_mismatch';
  end if;
  insert into public.dw_actor_attribution_jobs(tenant_id,watchlist_id,status,next_attempt_at)
  values(p_tenant_id,p_watchlist_id,'queued',now())
  on conflict (tenant_id,watchlist_id) where status in ('queued','running')
  do update set next_attempt_at=least(public.dw_actor_attribution_jobs.next_attempt_at,now()),
                updated_at=now()
  returning job_id into v_job;
  return v_job;
end $$;

create or replace function public.claim_dw_attribution_jobs(p_limit integer default 25)
returns setof public.dw_actor_attribution_jobs language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  return query
  with candidates as (
    select j.job_id from public.dw_actor_attribution_jobs j
    where ((j.status='queued' and j.next_attempt_at <= now()) or (j.status='running' and j.locked_at < now()-interval '10 minutes'))
    order by j.next_attempt_at, j.created_at
    for update skip locked limit greatest(1,least(coalesce(p_limit,25),100))
  )
  update public.dw_actor_attribution_jobs j set status='running',locked_at=now(),attempts=j.attempts+1,updated_at=now()
  from candidates c where j.job_id=c.job_id returning j.*;
end $$;

create or replace function public.finish_dw_attribution_job(p_job_id uuid, p_error_code text default null)
returns void language plpgsql security definer set search_path = pg_catalog, public as $$
begin
  update public.dw_actor_attribution_jobs
  set status=case when p_error_code is null then 'done' when attempts < 8 then 'queued' else 'failed' end,
      last_error_code=left(p_error_code,80),
      next_attempt_at=case when p_error_code is null then next_attempt_at else now() + make_interval(secs => least(3600, power(2, least(attempts,10))::integer)) end,
      locked_at=null,updated_at=now()
  where job_id=p_job_id;
end $$;

revoke all on function public.enqueue_dw_attribution_job(uuid,uuid) from public, anon, authenticated;
revoke all on function public.claim_dw_attribution_jobs(integer) from public, anon, authenticated;
revoke all on function public.finish_dw_attribution_job(uuid,text) from public, anon, authenticated;
grant execute on function public.enqueue_dw_attribution_job(uuid,uuid) to service_role;
grant execute on function public.claim_dw_attribution_jobs(integer) to service_role;
grant execute on function public.finish_dw_attribution_job(uuid,text) to service_role;

-- Actor profiles can be global public CTI or tenant-private provisional clusters.
-- Public profile access remains through the authenticated API only.
