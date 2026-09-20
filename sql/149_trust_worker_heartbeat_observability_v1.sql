-- 149_trust_worker_heartbeat_observability_v1.sql
begin;
create table if not exists public.trust_worker_heartbeats (
 worker_name text primary key,status text not null check(status in ('STARTING','RUNNING','STOPPING','ERROR')),
 last_heartbeat_at timestamptz not null default now(),last_success_at timestamptz,last_error_at timestamptz,last_error_code text,metadata jsonb not null default '{}'::jsonb);
alter table public.trust_worker_heartbeats enable row level security;
revoke all on public.trust_worker_heartbeats from public,anon,authenticated;
create or replace function public.trust_worker_heartbeat(p_worker_name text,p_status text,p_success boolean default false,p_error_code text default null,p_metadata jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path=public,pg_catalog as $$
begin
 if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
 insert into public.trust_worker_heartbeats(worker_name,status,last_heartbeat_at,last_success_at,last_error_at,last_error_code,metadata)
 values(p_worker_name,p_status,now(),case when p_success then now() end,case when p_error_code is not null then now() end,p_error_code,coalesce(p_metadata,'{}'::jsonb))
 on conflict(worker_name) do update set status=excluded.status,last_heartbeat_at=excluded.last_heartbeat_at,last_success_at=case when p_success then now() else trust_worker_heartbeats.last_success_at end,last_error_at=case when p_error_code is not null then now() else trust_worker_heartbeats.last_error_at end,last_error_code=case when p_error_code is not null then p_error_code else trust_worker_heartbeats.last_error_code end,metadata=excluded.metadata;
end; $$;
revoke all on function public.trust_worker_heartbeat(text,text,boolean,text,jsonb) from public,anon,authenticated;
grant execute on function public.trust_worker_heartbeat(text,text,boolean,text,jsonb) to service_role;
commit;