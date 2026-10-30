-- Cyclothone Phase 2: assignment-scoped protective intelligence.
-- Location observations are short-lived, purpose-bound and inaccessible to direct clients.
-- Only authorized server-side routes (service role + explicit API scopes) may mutate/read them.

create extension if not exists pg_cron with schema pg_catalog;

create table if not exists public.vip_assignments (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_name text not null check (length(trim(assignment_name)) between 1 and 160),
    purpose text not null check (length(trim(purpose)) between 1 and 500),
    subject_ref_sha256 text not null check (subject_ref_sha256 ~ '^[0-9a-f]{64}$'),
    authorization_ref_sha256 text not null check (authorization_ref_sha256 ~ '^[0-9a-f]{64}$'),
    consent_evidence_sha256 text not null check (consent_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    start_time timestamptz not null,
    end_time timestamptz not null,
    status text not null default 'pending_approval'
        check (status in ('pending_approval','active','closed','expired')),
    created_by text not null,
    approved_by text,
    approved_at timestamptz,
    closed_at timestamptz,
    expired_at timestamptz,
    created_at timestamptz not null default now(),
    check (end_time > start_time),
    check (end_time <= start_time + interval '14 days'),
    unique (tenant_id, id),
    check ((status = 'pending_approval' and approved_by is null and approved_at is null)
        or (status = 'active' and approved_by is not null and approved_at is not null)
        or status in ('closed','expired'))
);
create index if not exists vip_assignments_tenant_active_idx
    on public.vip_assignments(tenant_id, status, start_time, end_time);

create table if not exists public.vip_location_pings (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    source_type text not null check (source_type in
        ('adsb_flight','public_event','authorized_socmint','consented_location_share')),
    latitude double precision not null check (latitude between -90 and 90),
    longitude double precision not null check (longitude between -180 and 180),
    observed_at timestamptz not null,
    source_ref_sha256 text not null check (source_ref_sha256 ~ '^[0-9a-f]{64}$'),
    evidence_sha256 text not null check (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    recorded_by text not null,
    created_at timestamptz not null default now(),
    unique (assignment_id, source_ref_sha256, observed_at),
    unique (tenant_id, id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_location_pings_assignment_time_idx
    on public.vip_location_pings(tenant_id, assignment_id, observed_at desc);

create table if not exists public.vip_threat_intersections (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    assignment_id uuid not null references public.vip_assignments(id) on delete cascade,
    threat_finding_id bigint not null references public.dw_findings(id) on delete cascade,
    location_ping_id uuid not null references public.vip_location_pings(id) on delete cascade,
    distance_km numeric(10,3) not null check (distance_km >= 0 and distance_km <= 50),
    time_delta_seconds integer not null check (time_delta_seconds between 0 and 172800),
    threat_evidence_sha256 text not null check (threat_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now(),
    unique (assignment_id, threat_finding_id, location_ping_id),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade,
    foreign key (tenant_id, location_ping_id)
        references public.vip_location_pings(tenant_id, id) on delete cascade
);
create index if not exists vip_intersections_tenant_created_idx
    on public.vip_threat_intersections(tenant_id, assignment_id, created_at desc);

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
        ('created','approved','observation_recorded','intersection_recorded','sos_raised',
         'closed','expired_purged','retention_purged')),
    actor text not null,
    event_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    foreign key (tenant_id, assignment_id)
        references public.vip_assignments(tenant_id, id) on delete cascade
);
create index if not exists vip_assignment_events_tenant_idx
    on public.vip_assignment_events(tenant_id, assignment_id, event_at desc);

alter table public.vip_assignments enable row level security;
alter table public.vip_location_pings enable row level security;
alter table public.vip_threat_intersections enable row level security;
alter table public.vip_protection_incidents enable row level security;
alter table public.vip_assignment_events enable row level security;

revoke all on public.vip_assignments, public.vip_location_pings,
    public.vip_threat_intersections, public.vip_protection_incidents,
    public.vip_assignment_events from public, anon, authenticated;
grant select, insert, update on public.vip_assignments to service_role;
grant select, insert, delete on public.vip_location_pings to service_role;
grant select, insert on public.vip_threat_intersections,
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
before update or delete on public.vip_assignment_events
for each row execute function public.vip_assignment_event_immutable();

create or replace function public.vip_create_assignment(
    p_tenant_id uuid,
    p_actor text,
    p_subject_ref text,
    p_assignment_name text,
    p_purpose text,
    p_start_time timestamptz,
    p_end_time timestamptz,
    p_authorization_ref text,
    p_consent_evidence_sha256 text
) returns public.vip_assignments
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_row public.vip_assignments;
begin
    if p_actor is null or length(trim(p_actor)) = 0
       or p_subject_ref is null or length(trim(p_subject_ref)) < 8
       or p_assignment_name is null or length(trim(p_assignment_name)) not between 1 and 160
       or p_purpose is null or length(trim(p_purpose)) not between 1 and 500
       or p_authorization_ref is null or length(trim(p_authorization_ref)) < 8
       or p_consent_evidence_sha256 is null
       or p_consent_evidence_sha256 !~ '^[0-9a-f]{64}
       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' then
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        tenant_id, assignment_name, purpose, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        p_tenant_id, trim(p_assignment_name), trim(p_purpose),
        encode(digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time, trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', trim(p_actor),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14));
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
       set status = 'active', approved_by = trim(p_actor), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> trim(p_actor)
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', trim(p_actor),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_record_location_observation(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_source_type text,
    p_latitude double precision, p_longitude double precision, p_observed_at timestamptz,
    p_source_ref text, p_evidence_sha256 text
) returns public.vip_location_pings
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_assignment public.vip_assignments; v_row public.vip_location_pings;
begin
    select * into v_assignment from public.vip_assignments
     where id = p_assignment_id and tenant_id = p_tenant_id for update;
    if v_assignment.id is null or v_assignment.status <> 'active'
       or now() < v_assignment.start_time or now() >= v_assignment.end_time
       or p_observed_at < v_assignment.start_time or p_observed_at > now() + interval '5 minutes'
       or p_observed_at < now() - interval '24 hours'
       or p_source_type not in ('adsb_flight','public_event','authorized_socmint','consented_location_share')
       or p_latitude is null or p_latitude not between -90 and 90
       or p_longitude is null or p_longitude not between -180 and 180
       or p_source_ref is null or length(trim(p_source_ref)) < 8
       or p_evidence_sha256 is null
       or p_evidence_sha256 !~ '^[0-9a-f]{64}
        raise exception 'observation outside active assignment or provenance requirements';
    end if;
    if (select count(*) from public.vip_location_pings where assignment_id = p_assignment_id) >= 500 then
        raise exception 'assignment observation cap reached';
    end if;
    insert into public.vip_location_pings(
        tenant_id, assignment_id, source_type, latitude, longitude, observed_at,
        source_ref_sha256, evidence_sha256, recorded_by
    ) values (
        p_tenant_id, p_assignment_id, p_source_type, p_latitude, p_longitude, p_observed_at,
        encode(digest(trim(p_source_ref), 'sha256'), 'hex'), lower(p_evidence_sha256), trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'observation_recorded', trim(p_actor),
        jsonb_build_object('source_type', p_source_type, 'evidence_sha256', lower(p_evidence_sha256)));
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
     where id = p_assignment_id and tenant_id = p_tenant_id and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_location_pings where assignment_id = p_assignment_id;
    get diagnostics v_deleted = row_count;
    delete from public.vip_threat_intersections where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', trim(p_actor),
        jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
        delete from public.vip_location_pings where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        delete from public.vip_threat_intersections where assignment_id = v_assignment.id;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', 'system:pg_cron',
            jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', trim(p_summary), trim(p_actor))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', trim(p_actor),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

-- Hourly retention backstop. Explicit close also purges synchronously.
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '0 * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;

       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' then
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        tenant_id, assignment_name, purpose, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        p_tenant_id, trim(p_assignment_name), trim(p_purpose),
        encode(digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time, trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', trim(p_actor),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14));
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
       set status = 'active', approved_by = trim(p_actor), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> trim(p_actor)
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', trim(p_actor),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_record_location_observation(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_source_type text,
    p_latitude double precision, p_longitude double precision, p_observed_at timestamptz,
    p_source_ref text, p_evidence_sha256 text
) returns public.vip_location_pings
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_assignment public.vip_assignments; v_row public.vip_location_pings;
begin
    select * into v_assignment from public.vip_assignments
     where id = p_assignment_id and tenant_id = p_tenant_id for update;
    if v_assignment.id is null or v_assignment.status <> 'active'
       or now() < v_assignment.start_time or now() >= v_assignment.end_time
       or p_observed_at < v_assignment.start_time or p_observed_at > now() + interval '5 minutes'
       or p_observed_at < now() - interval '24 hours'
       or p_source_type not in ('adsb_flight','public_event','authorized_socmint','consented_location_share')
       or p_latitude is null or p_latitude not between -90 and 90
       or p_longitude is null or p_longitude not between -180 and 180
       or p_source_ref is null or length(trim(p_source_ref)) < 8
       or p_evidence_sha256 !~ '^[0-9a-f]{64}$' THEN
        raise exception 'observation outside active assignment or provenance requirements';
    end if;
    if (select count(*) from public.vip_location_pings where assignment_id = p_assignment_id) >= 500 then
        raise exception 'assignment observation cap reached';
    end if;
    insert into public.vip_location_pings(
        tenant_id, assignment_id, source_type, latitude, longitude, observed_at,
        source_ref_sha256, evidence_sha256, recorded_by
    ) values (
        p_tenant_id, p_assignment_id, p_source_type, p_latitude, p_longitude, p_observed_at,
        encode(digest(trim(p_source_ref), 'sha256'), 'hex'), lower(p_evidence_sha256), trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'observation_recorded', trim(p_actor),
        jsonb_build_object('source_type', p_source_type, 'evidence_sha256', lower(p_evidence_sha256)));
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
     where id = p_assignment_id and tenant_id = p_tenant_id and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_location_pings where assignment_id = p_assignment_id;
    get diagnostics v_deleted = row_count;
    delete from public.vip_threat_intersections where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', trim(p_actor),
        jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
        delete from public.vip_location_pings where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        delete from public.vip_threat_intersections where assignment_id = v_assignment.id;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', 'system:pg_cron',
            jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', trim(p_summary), trim(p_actor))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', trim(p_actor),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

-- Hourly retention backstop. Explicit close also purges synchronously.
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '0 * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
 THEN
        raise exception 'observation outside active assignment or provenance requirements';
    end if;
    if (select count(*) from public.vip_location_pings where assignment_id = p_assignment_id) >= 500 then
        raise exception 'assignment observation cap reached';
    end if;
    insert into public.vip_location_pings(
        tenant_id, assignment_id, source_type, latitude, longitude, observed_at,
        source_ref_sha256, evidence_sha256, recorded_by
    ) values (
        p_tenant_id, p_assignment_id, p_source_type, p_latitude, p_longitude, p_observed_at,
        encode(digest(trim(p_source_ref), 'sha256'), 'hex'), lower(p_evidence_sha256), trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'observation_recorded', trim(p_actor),
        jsonb_build_object('source_type', p_source_type, 'evidence_sha256', lower(p_evidence_sha256)));
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
     where id = p_assignment_id and tenant_id = p_tenant_id and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_location_pings where assignment_id = p_assignment_id;
    get diagnostics v_deleted = row_count;
    delete from public.vip_threat_intersections where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', trim(p_actor),
        jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
        delete from public.vip_location_pings where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        delete from public.vip_threat_intersections where assignment_id = v_assignment.id;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', 'system:pg_cron',
            jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', trim(p_summary), trim(p_actor))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', trim(p_actor),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

-- Hourly retention backstop. Explicit close also purges synchronously.
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '0 * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;

       or p_start_time is null or p_end_time is null
       or p_end_time <= p_start_time
       or p_end_time > p_start_time + interval '14 days' THEN
        raise exception 'invalid assignment authorization or bounded duration';
    end if;
    if p_start_time < now() - interval '5 minutes' or p_start_time > now() + interval '30 days' then
        raise exception 'assignment start time outside permitted window';
    end if;
    insert into public.vip_assignments(
        tenant_id, assignment_name, purpose, subject_ref_sha256,
        authorization_ref_sha256, consent_evidence_sha256, start_time, end_time, created_by
    ) values (
        p_tenant_id, trim(p_assignment_name), trim(p_purpose),
        encode(digest(trim(p_subject_ref), 'sha256'), 'hex'),
        encode(digest(trim(p_authorization_ref), 'sha256'), 'hex'),
        lower(p_consent_evidence_sha256), p_start_time, p_end_time, trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'created', trim(p_actor),
        jsonb_build_object('approval_required', true, 'maximum_duration_days', 14));
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
       set status = 'active', approved_by = trim(p_actor), approved_at = now()
     where id = p_assignment_id and tenant_id = p_tenant_id
       and status = 'pending_approval' and created_by <> trim(p_actor)
       and end_time > now()
    returning * into v_row;
    if v_row.id is null then
        raise exception 'assignment not found, expired, already approved, or dual-control failed';
    end if;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, v_row.id, 'approved', trim(p_actor),
        jsonb_build_object('separation_of_duties', true));
    return v_row;
end;
$$;

create or replace function public.vip_record_location_observation(
    p_tenant_id uuid, p_assignment_id uuid, p_actor text, p_source_type text,
    p_latitude double precision, p_longitude double precision, p_observed_at timestamptz,
    p_source_ref text, p_evidence_sha256 text
) returns public.vip_location_pings
language plpgsql security invoker set search_path = pg_catalog, public as $$
declare v_assignment public.vip_assignments; v_row public.vip_location_pings;
begin
    select * into v_assignment from public.vip_assignments
     where id = p_assignment_id and tenant_id = p_tenant_id for update;
    if v_assignment.id is null or v_assignment.status <> 'active'
       or now() < v_assignment.start_time or now() >= v_assignment.end_time
       or p_observed_at < v_assignment.start_time or p_observed_at > now() + interval '5 minutes'
       or p_observed_at < now() - interval '24 hours'
       or p_source_type not in ('adsb_flight','public_event','authorized_socmint','consented_location_share')
       or p_latitude is null or p_latitude not between -90 and 90
       or p_longitude is null or p_longitude not between -180 and 180
       or p_source_ref is null or length(trim(p_source_ref)) < 8
       or p_evidence_sha256 !~ '^[0-9a-f]{64}$' THEN
        raise exception 'observation outside active assignment or provenance requirements';
    end if;
    if (select count(*) from public.vip_location_pings where assignment_id = p_assignment_id) >= 500 then
        raise exception 'assignment observation cap reached';
    end if;
    insert into public.vip_location_pings(
        tenant_id, assignment_id, source_type, latitude, longitude, observed_at,
        source_ref_sha256, evidence_sha256, recorded_by
    ) values (
        p_tenant_id, p_assignment_id, p_source_type, p_latitude, p_longitude, p_observed_at,
        encode(digest(trim(p_source_ref), 'sha256'), 'hex'), lower(p_evidence_sha256), trim(p_actor)
    ) returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'observation_recorded', trim(p_actor),
        jsonb_build_object('source_type', p_source_type, 'evidence_sha256', lower(p_evidence_sha256)));
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
     where id = p_assignment_id and tenant_id = p_tenant_id and status in ('active','pending_approval')
    returning * into v_row;
    if v_row.id is null then raise exception 'active assignment not found'; end if;
    delete from public.vip_location_pings where assignment_id = p_assignment_id;
    get diagnostics v_deleted = row_count;
    delete from public.vip_threat_intersections where assignment_id = p_assignment_id;
    update public.vip_assignments
       set assignment_name = 'REDACTED', purpose = 'REDACTED',
           subject_ref_sha256 = repeat('0',64),
           authorization_ref_sha256 = repeat('0',64),
           consent_evidence_sha256 = repeat('0',64)
     where id = p_assignment_id;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'closed', trim(p_actor),
        jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
        delete from public.vip_location_pings where assignment_id = v_assignment.id;
        get diagnostics v_deleted = row_count;
        v_total := v_total + v_deleted;
        delete from public.vip_threat_intersections where assignment_id = v_assignment.id;
        update public.vip_assignments
           set status = 'expired', expired_at = now(),
               assignment_name = 'REDACTED', purpose = 'REDACTED',
               subject_ref_sha256 = repeat('0',64),
               authorization_ref_sha256 = repeat('0',64),
               consent_evidence_sha256 = repeat('0',64)
         where id = v_assignment.id;
        insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
        values (v_assignment.tenant_id, v_assignment.id, 'expired_purged', 'system:pg_cron',
            jsonb_build_object('location_rows_deleted', v_deleted, 'pii_redacted', true));
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
    ) values (p_tenant_id, p_assignment_id, 'sos', 'P1', trim(p_summary), trim(p_actor))
    returning * into v_row;
    insert into public.vip_assignment_events(tenant_id, assignment_id, event_type, actor, metadata)
    values (p_tenant_id, p_assignment_id, 'sos_raised', trim(p_actor),
        jsonb_build_object('incident_id', v_row.id, 'priority', 'P1',
                           'dispatch_status', 'not_dispatched', 'human_response_required', true));
    return v_row;
end;
$$;

revoke all on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_approve_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) from public, anon, authenticated;
revoke all on function public.vip_close_assignment(uuid,uuid,text) from public, anon, authenticated;
revoke all on function public.purge_expired_vip_data() from public, anon, authenticated;
revoke all on function public.vip_raise_sos(uuid,uuid,text,text) from public, anon, authenticated;
grant execute on function public.vip_create_assignment(uuid,text,text,text,text,timestamptz,timestamptz,text,text) to service_role;
grant execute on function public.vip_approve_assignment(uuid,uuid,text) to service_role;
grant execute on function public.vip_record_location_observation(uuid,uuid,text,text,double precision,double precision,timestamptz,text,text) to service_role;
grant execute on function public.vip_close_assignment(uuid,uuid,text) to service_role;
grant execute on function public.purge_expired_vip_data() to service_role;
grant execute on function public.vip_raise_sos(uuid,uuid,text,text) to service_role;

-- Hourly retention backstop. Explicit close also purges synchronously.
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
          from cron.job where jobname = 'vip-assignment-retention-hourly';
        perform cron.schedule(
            'vip-assignment-retention-hourly',
            '0 * * * *',
            'select public.purge_expired_vip_data();'
        );
    end if;
end;
$$;
