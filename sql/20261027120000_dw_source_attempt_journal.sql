-- Cyclothone Source-Attempt Journal v1.
-- Additive only. This migration is intentionally NOT applied to Supabase production here.
-- The existing request lease is represented by service_requests.attempts + locked_until;
-- this schema does not invent a lease UUID, session_id, or asset_id relationship.

create type public.source_outcome as enum (
  'succeeded',
  'succeeded_empty',
  'partial_parse',
  'source_unavailable',
  'source_rate_limited',
  'source_auth_failed',
  'parser_drift',
  'poisoned_input',
  'aborted_by_policy',
  'aborted_by_lease'
);

create table public.source_attempts (
  attempt_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  request_id uuid not null references public.service_requests(id) on delete restrict,
  service_key text not null check (length(service_key) between 1 and 120),
  source_key text not null check (length(source_key) between 1 and 160),
  connector_version text not null check (length(connector_version) between 1 and 160),
  parser_version text not null check (length(parser_version) between 1 and 80),
  window_start timestamptz not null,
  window_end timestamptz not null,
  fencing_token bigint not null check (fencing_token > 0),
  worker_id text not null check (length(worker_id) between 1 and 160),
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  outcome public.source_outcome,
  http_status integer check (http_status between 100 and 599),
  bytes_received bigint check (bytes_received >= 0),
  parse_success boolean,
  selector_miss boolean,
  findings_count integer check (findings_count >= 0),
  evidence_refs text[] not null default '{}',
  error_class text check (error_class is null or length(error_class) <= 100),
  error_code text check (error_code is null or error_code ~ '^[a-z][a-z0-9_]{0,79}$'),
  idempotency_key text not null unique check (idempotency_key ~ '^[a-f0-9]{64}$'),
  supersedes_attempt_id uuid references public.source_attempts(attempt_id) on delete restrict,
  created_at timestamptz not null default now(),
  check (window_end >= window_start),
  check ((completed_at is null and outcome is null) or (completed_at is not null and outcome is not null)),
  check (completed_at is null or completed_at >= started_at),
  check (outcome <> 'succeeded_empty' or (parse_success is true and findings_count = 0)),
  check (outcome <> 'partial_parse' or parse_success is true),
  check (outcome <> 'parser_drift' or selector_miss is true),
  check (outcome <> 'succeeded' or (parse_success is true and coalesce(findings_count, 0) > 0)),
  check (outcome <> 'aborted_by_lease' or completed_at is not null)
);

create index source_attempts_tenant_request_idx
  on public.source_attempts (tenant_id, request_id, started_at desc);
create index source_attempts_source_time_idx
  on public.source_attempts (source_key, started_at desc);
create index source_attempts_outcome_time_idx
  on public.source_attempts (outcome, completed_at desc);

alter table public.source_attempts enable row level security;
revoke all on public.source_attempts from public, anon, authenticated;
grant select on public.source_attempts to service_role;

create or replace function public.source_attempts_guard_update()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if old.completed_at is not null then
    raise exception 'source_attempt_terminal_immutable';
  end if;
  if new.attempt_id is distinct from old.attempt_id
     or new.tenant_id is distinct from old.tenant_id
     or new.request_id is distinct from old.request_id
     or new.service_key is distinct from old.service_key
     or new.source_key is distinct from old.source_key
     or new.connector_version is distinct from old.connector_version
     or new.parser_version is distinct from old.parser_version
     or new.window_start is distinct from old.window_start
     or new.window_end is distinct from old.window_end
     or new.fencing_token is distinct from old.fencing_token
     or new.worker_id is distinct from old.worker_id
     or new.started_at is distinct from old.started_at
     or new.idempotency_key is distinct from old.idempotency_key
     or new.supersedes_attempt_id is distinct from old.supersedes_attempt_id
     or new.created_at is distinct from old.created_at then
    raise exception 'source_attempt_identity_immutable';
  end if;
  if old.completed_at is not null and new.completed_at is distinct from old.completed_at then
    raise exception 'source_attempt_completed_at_immutable';
  end if;
  return new;
end $$;

create trigger source_attempts_guard_update
before update on public.source_attempts
for each row execute function public.source_attempts_guard_update();

create or replace function public.source_attempts_no_delete()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  raise exception 'source_attempt_append_only';
end $$;

create trigger source_attempts_no_delete
before delete on public.source_attempts
for each row execute function public.source_attempts_no_delete();

-- Starts an attempt only while the worker owns the current request lease.
-- The request attempt counter is the existing fencing token in this version.
-- Idempotency is SHA-256 over canonical JSON array values to avoid delimiter ambiguity.
create or replace function public.begin_source_attempt(
  p_request_id uuid,
  p_fencing_token bigint,
  p_source_key text,
  p_connector_version text,
  p_parser_version text,
  p_window_start timestamptz,
  p_window_end timestamptz,
  p_worker_id text
) returns public.source_attempts
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_request public.service_requests%rowtype;
  v_tenant_id uuid;
  v_key text;
  v_attempt public.source_attempts%rowtype;
begin
  if p_request_id is null or p_fencing_token is null or p_fencing_token < 1
     or nullif(trim(p_source_key), '') is null
     or nullif(trim(p_connector_version), '') is null
     or nullif(trim(p_parser_version), '') is null
     or nullif(trim(p_worker_id), '') is null
     or p_window_start is null or p_window_end is null or p_window_end < p_window_start then
    raise exception 'invalid_source_attempt_parameters';
  end if;

  select * into v_request
    from public.service_requests
   where id = p_request_id
   for update;
  if not found then raise exception 'service_request_not_found'; end if;
  if v_request.service_key <> 'dark_web_monitoring' then
    raise exception 'unsupported_source_attempt_service';
  end if;
  if v_request.processing_state <> 'running'
     or v_request.attempts::bigint <> p_fencing_token
     or v_request.locked_until is null
     or v_request.locked_until <= now() then
    raise exception 'source_attempt_lease_rejected';
  end if;

  select co.tenant_id into v_tenant_id
    from public.customer_organizations co
   where co.id = v_request.organization_id;
  if v_tenant_id is null then raise exception 'source_attempt_tenant_unresolved'; end if;

  v_key := encode(digest(convert_to(jsonb_build_array(
    v_tenant_id::text,
    coalesce(v_request.target, ''),
    v_request.service_key,
    p_source_key,
    p_window_start,
    p_connector_version
  )::text, 'UTF8'), 'sha256'), 'hex');

  select * into v_attempt from public.source_attempts where idempotency_key = v_key;
  if found then
    if v_attempt.request_id <> p_request_id
       or v_attempt.tenant_id <> v_tenant_id
       or v_attempt.source_key <> p_source_key
       or v_attempt.parser_version <> p_parser_version
       or v_attempt.window_start <> p_window_start
       or v_attempt.window_end <> p_window_end then
      raise exception 'source_attempt_idempotency_conflict';
    end if;
    return v_attempt;
  end if;

  insert into public.source_attempts (
    tenant_id, request_id, service_key, source_key, connector_version,
    parser_version, window_start, window_end, fencing_token, worker_id, idempotency_key
  ) values (
    v_tenant_id, p_request_id, v_request.service_key, p_source_key, p_connector_version,
    p_parser_version, p_window_start, p_window_end, p_fencing_token, p_worker_id, v_key
  ) returning * into v_attempt;
  return v_attempt;
end $$;

-- Completion validates the *current* request lease atomically. A stale worker cannot
-- finalize even if its journal row was created before the lease expired.
create or replace function public.complete_source_attempt(
  p_attempt_id uuid,
  p_fencing_token bigint,
  p_outcome public.source_outcome,
  p_http_status integer default null,
  p_bytes_received bigint default null,
  p_parse_success boolean default null,
  p_selector_miss boolean default null,
  p_findings_count integer default null,
  p_evidence_refs text[] default '{}',
  p_error_class text default null,
  p_error_code text default null
) returns public.source_attempts
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_attempt public.source_attempts%rowtype;
  v_request public.service_requests%rowtype;
begin
  select * into v_attempt
    from public.source_attempts
   where attempt_id = p_attempt_id
   for update;
  if not found then raise exception 'source_attempt_not_found'; end if;
  if v_attempt.completed_at is not null then
    if v_attempt.fencing_token = p_fencing_token and v_attempt.outcome = p_outcome then
      return v_attempt;
    end if;
    raise exception 'source_attempt_terminal_immutable';
  end if;
  if v_attempt.fencing_token <> p_fencing_token then
    raise exception 'source_attempt_fencing_token_mismatch';
  end if;

  select * into v_request
    from public.service_requests
   where id = v_attempt.request_id
   for update;
  if not found
     or v_request.processing_state <> 'running'
     or v_request.attempts::bigint <> p_fencing_token
     or v_request.locked_until is null
     or v_request.locked_until <= now() then
    raise exception 'source_attempt_lease_rejected';
  end if;

  if p_outcome is null or p_findings_count is not null and p_findings_count < 0
     or p_bytes_received is not null and p_bytes_received < 0
     or p_http_status is not null and p_http_status not between 100 and 599
     or p_error_code is not null and p_error_code !~ '^[a-z][a-z0-9_]{0,79}$' then
    raise exception 'invalid_source_attempt_completion';
  end if;
  if p_outcome = 'succeeded_empty' and (p_parse_success is distinct from true or p_findings_count is distinct from 0) then
    raise exception 'succeeded_empty_requires_successful_empty_parse';
  end if;
  if p_outcome = 'succeeded' and (p_parse_success is distinct from true or coalesce(p_findings_count, 0) < 1) then
    raise exception 'succeeded_requires_findings';
  end if;
  if p_outcome = 'parser_drift' and p_selector_miss is distinct from true then
    raise exception 'parser_drift_requires_selector_miss';
  end if;
  if exists (select 1 from unnest(coalesce(p_evidence_refs, '{}')) ref where ref !~ '^[a-f0-9]{64}$') then
    raise exception 'invalid_evidence_reference_hash';
  end if;

  update public.source_attempts
     set completed_at = now(),
         outcome = p_outcome,
         http_status = p_http_status,
         bytes_received = p_bytes_received,
         parse_success = p_parse_success,
         selector_miss = p_selector_miss,
         findings_count = p_findings_count,
         evidence_refs = coalesce(p_evidence_refs, '{}'),
         error_class = p_error_class,
         error_code = p_error_code
   where attempt_id = p_attempt_id
   returning * into v_attempt;
  return v_attempt;
end $$;

revoke all on function public.begin_source_attempt(uuid,bigint,text,text,text,timestamptz,timestamptz,text) from public, anon, authenticated;
revoke all on function public.complete_source_attempt(uuid,bigint,public.source_outcome,integer,bigint,boolean,boolean,integer,text[],text,text) from public, anon, authenticated;
grant execute on function public.begin_source_attempt(uuid,bigint,text,text,text,timestamptz,timestamptz,text) to service_role;
grant execute on function public.complete_source_attempt(uuid,bigint,public.source_outcome,integer,bigint,boolean,boolean,integer,text[],text,text) to service_role;
