-- Cyclothone change-event outbox and scoring contract.
-- This migration creates a durable, idempotent event ledger. It does not enable
-- Kafka, external source credentials, graph triggers, or customer alert delivery.
-- Apply only in a coordinated release with the matching API/worker code.

create table if not exists public.dw_change_events (
    event_id uuid primary key,
    event_type text not null check (event_type in (
        'NEW_ACCOUNT','PROFILE_MODIFICATION','NEW_POST','NEW_FOLLOWER',
        'BREACH_EXPOSURE','STEALER_LOG_APPEARANCE','DARK_WEB_MENTION',
        'TELEGRAM_MENTION','CODE_REPO_LEAK','INFRASTRUCTURE_CHANGE'
    )),
    subject_id text not null check (subject_id ~ '^[a-f0-9]{64}$'),
    change_score numeric(4,2) not null check (change_score >= 0 and change_score <= 10),
    tier text not null check (tier in ('immediate','scheduled','archive')),
    source_module text not null,
    source_name text not null,
    source_url text,
    collected_at timestamptz not null,
    change_details jsonb not null default '{}'::jsonb,
    raw_payload_hash text not null check (raw_payload_hash ~ '^[a-f0-9]{64}$'),
    screenshot_path text,
    rfc3161_timestamp_token text,
    payload jsonb not null,
    published_at timestamptz,
    publish_attempts integer not null default 0 check (publish_attempts >= 0),
    last_publish_error text,
    retention_until timestamptz not null default (now() + interval '90 days'),
    created_at timestamptz not null default now()
);

create index if not exists dw_change_events_pending_idx
    on public.dw_change_events(collected_at)
    where published_at is null;
create index if not exists dw_change_events_subject_idx
    on public.dw_change_events(subject_id, collected_at desc);
create index if not exists dw_change_events_tier_idx
    on public.dw_change_events(tier, collected_at desc);
alter table public.dw_change_events enable row level security;

create or replace function public.record_dw_change_event(p_event jsonb)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    saved_id uuid;
begin
    if jsonb_typeof(p_event) <> 'object' then
        raise exception 'invalid_change_event';
    end if;

    insert into public.dw_change_events (
        event_id, event_type, subject_id, change_score, tier,
        source_module, source_name, source_url, collected_at,
        change_details, raw_payload_hash, screenshot_path,
        rfc3161_timestamp_token, payload
    ) values (
        (p_event->>'event_id')::uuid,
        p_event->>'event_type',
        p_event->>'subject_id',
        (p_event->>'change_score')::numeric,
        p_event->>'tier',
        p_event->>'source_module',
        p_event->>'source_name',
        nullif(p_event->>'source_url', ''),
        (p_event->>'collected_at')::timestamptz,
        coalesce(p_event->'change_details', '{}'::jsonb),
        p_event->>'raw_payload_hash',
        nullif(p_event->>'screenshot_path', ''),
        nullif(p_event->>'rfc3161_timestamp_token', ''),
        p_event
    )
    on conflict (event_id) do nothing
    returning event_id into saved_id;

    return coalesce(saved_id, (p_event->>'event_id')::uuid);
end
$$;

create or replace function public.purge_expired_dw_change_events()
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare removed integer;
begin
    delete from public.dw_change_events
     where retention_until < now()
       and published_at is not null;
    get diagnostics removed = row_count;
    return removed;
end
$$;

revoke all on function public.record_dw_change_event(jsonb) from public, anon, authenticated;
revoke all on function public.purge_expired_dw_change_events() from public, anon, authenticated;
grant execute on function public.record_dw_change_event(jsonb) to service_role;
grant execute on function public.purge_expired_dw_change_events() to service_role;
