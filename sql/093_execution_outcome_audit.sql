-- 093_execution_outcome_audit.sql
-- Durable audit ledger for execution outcomes. The execution state remains
-- authoritative in ai_runs; this ledger records the exact terminal report.

create table if not exists public.ai_execution_outcomes (
  id uuid primary key default gen_random_uuid(),
  run_id uuid not null references public.ai_runs(id) on delete restrict,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  outcome text not null check (outcome in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED')),
  actual_cost_usd numeric(18,8) not null default 0 check (actual_cost_usd >= 0),
  error jsonb,
  actor text not null,
  reported_at timestamptz not null default now(),
  unique (run_id)
);

create or replace function public.ai_execution_outcomes_immutable()
returns trigger
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
begin
  if tg_op <> 'INSERT' then
    raise exception 'execution_outcome_immutable';
  end if;
  return new;
end;
$$;

create trigger trg_ai_execution_outcomes_immutable
before update or delete on public.ai_execution_outcomes
for each row execute function public.ai_execution_outcomes_immutable();

create index if not exists idx_ai_execution_outcomes_tenant_time
  on public.ai_execution_outcomes(tenant_id,reported_at desc);

alter table public.ai_execution_outcomes enable row level security;

revoke all on public.ai_execution_outcomes from public,anon,authenticated;
grant select,insert,update,delete on public.ai_execution_outcomes to service_role;

create or replace function public.ai_complete_execution(
  p_run_id uuid,
  p_outcome text,
  p_actual_cost_usd numeric(18,8) default 0,
  p_error jsonb default null,
  p_actor text default 'system'
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r public.ai_runs;
  v_committed boolean;
  v_existing public.ai_execution_outcomes;
begin
  if p_run_id is null
     or p_outcome not in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED')
     or p_actual_cost_usd is null
     or p_actual_cost_usd < 0 then
    raise exception 'invalid_execution_outcome';
  end if;

  select * into r from public.ai_runs where id=p_run_id for update;
  if not found then raise exception 'run_not_found'; end if;

  select exists (
    select 1 from public.ai_execution_provenance p where p.run_id=r.id
  ) into v_committed;

  if not v_committed then raise exception 'execution_not_committed'; end if;

  if r.run_state in ('COMPLETED','FAILED','CANCELLED','TIMEOUT','REJECTED') then
    select * into v_existing from public.ai_execution_outcomes where run_id=r.id;
    if v_existing.outcome is distinct from p_outcome then
      raise exception 'execution_already_finalized';
    end if;
    return jsonb_build_object(
      'completed',true,'idempotent',true,'run_id',r.id,
      'run_state',r.run_state,'cost_usd',r.cost_usd,
      'outcome_id',v_existing.id
    );
  end if;

  if p_outcome='COMPLETED' then
    perform public.ai_settle_execution(r.id,p_actual_cost_usd);
    perform public.ai_transition_run(r.id,'COMPLETED',coalesce(p_actor,'system'));
  else
    perform public.ai_release_execution(r.id);
    perform public.ai_transition_run(r.id,p_outcome,coalesce(p_actor,'system'));
  end if;

  if p_error is not null then
    update public.ai_runs set error=p_error where id=r.id;
  end if;

  insert into public.ai_execution_outcomes(
    run_id,tenant_id,outcome,actual_cost_usd,error,actor
  ) values (
    r.id,r.tenant_id,p_outcome,p_actual_cost_usd,p_error,left(coalesce(p_actor,'system'),128)
  )
  on conflict (run_id) do nothing;

  select * into r from public.ai_runs where id=r.id;
  select * into v_existing from public.ai_execution_outcomes where run_id=r.id;

  return jsonb_build_object(
    'completed',true,'idempotent',false,'run_id',r.id,
    'run_state',r.run_state,'cost_usd',r.cost_usd,
    'outcome_id',v_existing.id
  );
end;
$$;

revoke all on function public.ai_complete_execution(uuid,text,numeric,jsonb,text)
from public,anon,authenticated;
grant execute on function public.ai_complete_execution(uuid,text,numeric,jsonb,text)
to service_role;

comment on table public.ai_execution_outcomes is
'Immutable terminal execution outcome ledger; ai_runs remains the canonical execution state.';
