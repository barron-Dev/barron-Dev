-- Cyclothone Phase 2: controlled, assignment-scoped protective intelligence.
-- Privacy boundary: this module does not collect or persist a person's precise location,
-- device telemetry, flight path, hotel check-in, family graph, or live whereabouts.
-- It correlates authorized assignment regions/time windows with public threat records only.

create extension if not exists pg_cron with schema pg_catalog;

create table if not exists public.vip_assignments (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_name text not null check (length(trim(assignment_name)) between 1 and 160),
    purpose text not null check (length(trim(purpose)) between 8 and 500),
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    subject_ref_sha256 text not null check (subject_ref_sha256 ~ '^[0-9a-f]{64}$'),
    authorization_ref_sha256 text not null check (authorization_ref_sha256 ~ '^[0-9a-f]{64}$'),
    consent_evidence_sha256 text not null check (consent_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    start_time timestamptz not null,
    end_time timestamptz not null,
    status text not null default 'pending_approval'
        check (status in ('pending_approval','active','closed','expired')),
    created_by text not null check (created_by ~ '^[0-9a-f]{64}
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null check (raised_by ~ '^[0-9a-f]{64}
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null check (actor ~ '^[0-9a-f]{64} timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_by text check (approved_by is null or approved_by ~ '^[0-9a-f]{64}
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_by text check (approved_by is null or approved_by ~ '^[0-9a-f]{64}
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_by text check (approved_by is null or approved_by ~ '^[0-9a-f]{64}
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_by text check (approved_by is null or approved_by ~ '^[0-9a-f]{64}
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
),
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, id),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create unique index if not exists dw_findings_tenant_id_unique
    on public.dw_findings(tenant_id, id);

create table if not exists public.vip_region_threat_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    region_code text not null check (region_code ~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, threat_finding_id)
        references public.dw_findings(tenant_id, id) on delete cascade
);
create index if not exists vip_region_matches_tenant_created_idx
    on public.vip_region_threat_matches(tenant_id, assignment_id, created_at desc);

create table if not exists public.vip_protection_incidents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    incident_type text not null check (incident_type in ('sos','priority_alert')),
    priority text not null default 'P1' check (priority in ('P1','P2')),
    status text not null default 'raised' check (status in ('raised','acknowledged','resolved')),
    dispatch_status text not null default 'not_dispatched'
        check (dispatch_status in ('not_dispatched','human_authorized','dispatched','failed')),
    summary text not null check (length(trim(summary)) between 1 and 500),
    raised_by text not null,
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_incidents_tenant_created_idx
    on public.vip_protection_incidents(tenant_id, created_at desc);

create table if not exists public.vip_assignment_events (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    event_type text not null check (event_type in
        ('created','approved','region_match_recorded','sos_raised','closed','expired_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_region_threat_matches enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events
    from public, anon, authenticated, service_role;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert on public.vip_region_threat_matches,
    public.vip_protection_incidents, public.vip_assignment_events to service_role;
grant usage, select on sequence public.vip_assignment_events_id_seq to service_role;

create or replace function public.vip_assignment_event_immutable()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
    raise exception 'VIP assignment events are append-only';
end;
$$;
revoke all on function public.vip_assignment_event_immutable() from public, anon, authenticated;
drop trigger if exists vip_assignment_events_no_mutation on public.vip_assignment_events;
create trigger vip_assignment_events_no_mutation
before update on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid, p_actor text, p_subject_ref text, p_assignment_name text,
    p_purpose text, p_region_code text, p_start_time timestamptz, p_end_time timestamptz,
    p_authorization_ref text, p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_assignment_id uuid := gen_random_uuid();
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 8 and 500
       or p_region_code is null or p_region_code !~ '^[A-Z0-9][A-Z0-9_-]{1,31}$'
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}$'
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' THEN
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        id, tenant_id, assignment_name, purpose, region_code, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        v_assignment_id, p_tenant_id, trim(p_assignment_name), trim(p_purpose), p_region_code,
        encode(extensions.digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(extensions.digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time,
        encode(extensions.digest(trim(p_actor) || v_assignment_id::text, 'sha256'), 'hex')
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', encode(extensions.digest(trim(p_actor) || v_row.id::text, 'sha256'), 'hex'),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14,
                           'location_collection', false));
    return v_row;
end;
$$;

create or replace function public.vip_approve_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    update public.vip_assignments
       set status = 'active', approved_by = encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex')
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_close_assignment(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments; v_deleted integer;
begin
    update public.vip_assignments set status = 'closed', closed_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_region_threat_matches where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('region_matches_deleted', true, 'personal_fields_redacted', true));
    return v_row;
end;
$$;

create or replace function public.purge_expired_vip_data()
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare v_assignment record; v_deleted integer; v_total integer := 0;
begin
    for v_assignment in
        select id, tenant_id from public.vip_assignments
         where status in ('active','pending_approval') and end_time <= now()
         for update skip locked
    loop
        delete from public.vip_region_threat_matches where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED', region_code = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', encode(extensions.digest('system:pg_cron' || v_assignment.id::text, 'sha256'), 'hex'),
            jsonb_build_object('region_matches_deleted', v_deleted, 'personal_fields_redacted', true));
    end loop;
    return v_total;
end;
$$;

create or replace function public.vip_raise_sos(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_summary text
) returns public.vip_protection_incidents
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_protection_incidents;
begin
    if not exists (
        select 1 from public.vip_assignments
         where id = p_assignment_id and tenant_id = p_tenant_id
           and status = 'active' and start_time <= now() and end_time > now()
    ) then raise exception 'SOS requires an active assignment'; end if;
    insert into public.vip_protection_incidents(
        tenant_id, assignment_id, incident_type, priority, summary, raised_by
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', 'SOS activated by authorized agent', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', encode(extensions.digest(trim(p_actor) || p_assignment_id::text, 'sha256'), 'hex'),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '* * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
