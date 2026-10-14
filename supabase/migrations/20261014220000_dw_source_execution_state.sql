begin;

-- Provider run state is separate from Telegram endpoint inventory. Counts here
-- are provider executions, not endpoints, channels, findings, or alerts.
create table if not exists public.dw_source_execution_state (
  source_id text primary key references public.dw_sources(id) on delete cascade,
  last_status text not null,
  last_execution_at timestamptz not null default now(),
  last_execution_pulled boolean not null default false,
  execution_count bigint not null default 0 check (execution_count >= 0),
  successful_pull_count bigint not null default 0 check (successful_pull_count >= 0),
  failed_execution_count bigint not null default 0 check (failed_execution_count >= 0),
  last_error text,
  updated_at timestamptz not null default now()
);

create index if not exists dw_source_execution_state_recent_idx
  on public.dw_source_execution_state (last_execution_at desc);

alter table public.dw_source_execution_state enable row level security;
revoke all on table public.dw_source_execution_state from public, anon, authenticated;
grant select, insert, update, delete on table public.dw_source_execution_state to service_role;

create or replace function public.record_dw_source_execution(
  p_source_id text,
  p_status text,
  p_pulled boolean,
  p_error text default null
) returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if p_source_id is null or length(trim(p_source_id)) = 0 or length(p_source_id) > 100 then
    raise exception 'invalid dark web source id';
  end if;
  if p_status is null or length(trim(p_status)) = 0 or length(p_status) > 100 then
    raise exception 'invalid dark web source status';
  end if;
  if not exists (select 1 from public.dw_sources where id = p_source_id) then
    raise exception 'dark web source is not configured';
  end if;

  insert into public.dw_source_execution_state (
    source_id, last_status, last_execution_at, last_execution_pulled,
    execution_count, successful_pull_count, failed_execution_count,
    last_error, updated_at
  ) values (
    p_source_id, p_status, now(), coalesce(p_pulled, false),
    1, case when coalesce(p_pulled, false) then 1 else 0 end,
    case when coalesce(p_pulled, false) then 0 else 1 end,
    case when coalesce(p_pulled, false) then null else left(coalesce(p_error, p_status), 1000) end,
    now()
  )
  on conflict (source_id) do update set
    last_status = excluded.last_status,
    last_execution_at = excluded.last_execution_at,
    last_execution_pulled = excluded.last_execution_pulled,
    execution_count = public.dw_source_execution_state.execution_count + 1,
    successful_pull_count = public.dw_source_execution_state.successful_pull_count
      + case when excluded.last_execution_pulled then 1 else 0 end,
    failed_execution_count = public.dw_source_execution_state.failed_execution_count
      + case when excluded.last_execution_pulled then 0 else 1 end,
    last_error = excluded.last_error,
    updated_at = now();
end;
$$;

revoke all on function public.record_dw_source_execution(text,text,boolean,text) from public, anon, authenticated;
grant execute on function public.record_dw_source_execution(text,text,boolean,text) to service_role;

commit;
