-- Cyclothone Global Intelligence, Resilience and Platform Runtime Foundation Bundle
-- Consolidates existing source-controlled non-AI foundations 054-066 into one production rollout.
-- 059 autonomous-agent foundation is intentionally excluded because AI foundation is frozen.
-- This file does not create parallel systems; it promotes the existing canonical foundations together.
begin;

-- ===== SOURCE sql/054_global_platform.sql =====
-- sql/054_global_platform.sql
-- Global platform foundation. Preserves existing sql/051_fapi.sql.
-- Regions/catalog are data; runtime code never hardcodes a region list.

create table if not exists regions (
  code text primary key,
  name text not null,
  continent text not null,
  country text not null check (country ~ '^[A-Z]{2}$'),
  sovereignty_tier text not null default 'standard'
    check (sovereignty_tier in ('standard','gdpr','sovereign','govcloud')),
  api_base_url text not null,
  sandbox_base_url text not null,
  supabase_project text not null,
  storage_bucket text not null,
  kms_key_ref text not null,
  compliance jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists global_audit (
  id bigserial primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  region_code text not null references regions(code),
  actor text not null,
  action text not null,
  resource text not null,
  resource_id text,
  cross_border boolean not null default false,
  destination_region text references regions(code),
  legal_basis text,
  metadata jsonb not null default '{}'::jsonb,
  ip inet,
  ts timestamptz not null default now()
);
create index if not exists idx_global_audit_tenant_ts on global_audit(tenant_id, ts desc);
create index if not exists idx_global_audit_cross on global_audit(cross_border) where cross_border;

create table if not exists cross_region_metrics (
  source_region text not null references regions(code),
  tenant_id uuid not null references tenants(id) on delete cascade,
  metric_date date not null,
  detection_count int not null default 0 check (detection_count >= 0),
  blocked_count int not null default 0 check (blocked_count >= 0),
  case_count int not null default 0 check (case_count >= 0),
  device_count int not null default 0 check (device_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (source_region, tenant_id, metric_date)
);

alter table regions enable row level security;
alter table global_audit enable row level security;
alter table cross_region_metrics enable row level security;

drop policy if exists global_audit_tenant on global_audit;
create policy global_audit_tenant on global_audit for select to authenticated
using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists cross_region_metrics_tenant on cross_region_metrics;
create policy cross_region_metrics_tenant on cross_region_metrics for select to authenticated
using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

-- No client role gets direct writes to the audit/metrics tables.
revoke all on global_audit, cross_region_metrics from anon, authenticated;

create or replace function write_global_audit(
  p_tenant uuid, p_action text, p_resource text, p_resource_id text,
  p_actor text, p_cross_border boolean default false,
  p_dest_region text default null, p_legal_basis text default null,
  p_metadata jsonb default '{}'::jsonb
) returns void
language plpgsql security definer set search_path=public
as $$
begin
  if not exists (select 1 from tenants where id = p_tenant) then
    raise exception 'tenant not found';
  end if;
  insert into global_audit(
    tenant_id, region_code, actor, action, resource, resource_id,
    cross_border, destination_region, legal_basis, metadata
  ) values (
    p_tenant,
    current_setting('app.region', true),
    p_actor, p_action, p_resource, p_resource_id,
    p_cross_border, p_dest_region, p_legal_basis, coalesce(p_metadata,'{}'::jsonb)
  );
end $$;

revoke all on function write_global_audit(uuid,text,text,text,text,boolean,text,text,jsonb) from public, anon, authenticated;
grant execute on function write_global_audit(uuid,text,text,text,text,boolean,text,text,jsonb) to service_role;

create or replace function global_stats(p_tenant uuid, p_hours int default 24)
returns jsonb language sql stable security definer set search_path=public
as $$
  select jsonb_build_object(
    'detections',(select count(*) from detections where tenant_id=p_tenant and created_at > now()-(greatest(p_hours,1)||' hours')::interval),
    'blocked',(select count(*) from detections where tenant_id=p_tenant and verdict='block' and created_at > now()-(greatest(p_hours,1)||' hours')::interval),
    'cases',(select count(*) from crime_cases where tenant_id=p_tenant and created_at > now()-(greatest(p_hours,1)||' hours')::interval),
    'devices',(select count(*) from devices where tenant_id=p_tenant and status='active'),
    'alerts',(select count(*) from dw_alerts where tenant_id=p_tenant and status='new'),
    'catalog_peers',(select count(*) from federation_subscriptions where tenant_id=p_tenant and receive_enabled=true)
  );
$$;
revoke all on function global_stats(uuid,int) from public, anon, authenticated;
grant execute on function global_stats(uuid,int) to service_role;


-- ===== SOURCE sql/055_streaming_foundation.sql =====
-- Cyclothone streaming foundation. Does not replace existing migrations.
create table if not exists stream_topics (
  id text primary key,
  name text not null,
  category text not null check (category in ('endpoint','network','identity','cloud','physical','banking','telecom','satellite','ai','lens','federation')),
  schema_version int not null default 1 check (schema_version > 0),
  partition_count int not null default 12 check (partition_count > 0),
  retention_hours int not null default 168 check (retention_hours > 0),
  pii_level text not null default 'hashed' check (pii_level in ('public','hashed','encrypted','regulated')),
  enabled boolean not null default true
);

insert into stream_topics(id,name,category,partition_count,retention_hours,pii_level) values
('events.endpoint','Endpoint events','endpoint',24,168,'hashed'),
('events.network','Network events','network',24,168,'hashed'),
('events.identity','Identity events','identity',12,168,'encrypted'),
('events.cloud','Cloud workload events','cloud',12,168,'hashed'),
('events.physical','Physical access events','physical',12,720,'regulated'),
('events.banking','Banking transactions','banking',48,2160,'regulated'),
('events.telecom','Telecom signals','telecom',24,168,'regulated'),
('events.satellite','Satellite link events','satellite',6,720,'hashed'),
('events.ai','AI agent events','ai',12,168,'hashed'),
('events.lens','Lens findings','lens',6,720,'hashed'),
('events.federation','Federation events','federation',12,720,'encrypted'),
('detections.raw','Raw detections','endpoint',24,720,'hashed'),
('detections.fused','Fused detections','endpoint',24,720,'hashed'),
('commands.issued','Issued commands','endpoint',12,8760,'regulated'),
('commands.result','Command results','endpoint',12,8760,'regulated'),
('alerts.critical','Critical alerts fanout','endpoint',6,720,'hashed'),
('audit.global','Global audit stream','identity',6,17520,'regulated')
on conflict(id) do update set name=excluded.name, category=excluded.category,
schema_version=excluded.schema_version, partition_count=excluded.partition_count,
retention_hours=excluded.retention_hours, pii_level=excluded.pii_level;

create table if not exists stream_consumers (
  service_name text not null check (length(service_name) between 1 and 128),
  topic_id text not null references stream_topics(id) on delete cascade,
  region_code text not null references regions(code) on delete cascade,
  partition_id int not null check (partition_id >= 0),
  offset_value bigint not null default 0 check (offset_value >= 0),
  lag_seconds int not null default 0 check (lag_seconds >= 0),
  last_heartbeat timestamptz not null default now(),
  primary key(service_name,topic_id,region_code,partition_id)
);
create index if not exists idx_stream_consumers_lag on stream_consumers(lag_seconds desc) where lag_seconds > 60;

create table if not exists correlation_windows (
  window_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  correlation_key text not null,
  window_kind text not null check (window_kind in ('tumbling','sliding','session','graph')),
  window_start timestamptz not null,
  window_end timestamptz not null check (window_end >= window_start),
  event_count int not null default 0 check (event_count >= 0),
  severity_max text not null default 'low',
  state jsonb not null default '{}'::jsonb,
  closed boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists idx_corr_windows_tenant on correlation_windows(tenant_id,window_start desc);
create index if not exists idx_corr_windows_key on correlation_windows(tenant_id,correlation_key,window_start desc);
create index if not exists idx_corr_windows_open on correlation_windows(tenant_id) where closed=false;

create table if not exists stream_anomalies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  topic_id text not null references stream_topics(id),
  event_id uuid,
  correlation_key text not null,
  feature text not null,
  z_score double precision not null,
  value double precision not null,
  severity text not null check (severity in ('low','medium','high','critical')),
  score double precision not null check (score >= 0 and score <= 1),
  detected_at timestamptz not null default now()
);
create index if not exists idx_stream_anomalies_tenant_time on stream_anomalies(tenant_id,detected_at desc);

create table if not exists stream_dlq (
  id bigserial primary key,
  topic_id text not null references stream_topics(id),
  region_code text not null references regions(code),
  consumer text not null,
  payload jsonb not null,
  error text not null,
  attempts int not null default 1 check (attempts > 0),
  first_seen timestamptz not null default now(),
  last_attempt timestamptz not null default now()
);
create index if not exists idx_dlq_topic on stream_dlq(topic_id,first_seen desc);
create index if not exists idx_dlq_consumer on stream_dlq(consumer,last_attempt desc);

alter table stream_topics enable row level security;
alter table stream_consumers enable row level security;
alter table correlation_windows enable row level security;
alter table stream_anomalies enable row level security;
alter table stream_dlq enable row level security;

revoke all on stream_consumers,stream_dlq from anon,authenticated;
drop policy if exists stream_topics_read on stream_topics;
create policy stream_topics_read on stream_topics for select to authenticated using (enabled=true);
drop policy if exists corr_windows_tenant on correlation_windows;
create policy corr_windows_tenant on correlation_windows for select to authenticated
using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));
drop policy if exists stream_anomalies_tenant on stream_anomalies;
create policy stream_anomalies_tenant on stream_anomalies for select to authenticated
using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create or replace function stream_commit_offset(
  p_service text,p_topic text,p_region text,p_partition int,p_offset bigint,p_lag int
) returns void language plpgsql security definer set search_path=public as $$
begin
  if p_offset < 0 or p_partition < 0 or p_lag < 0 then raise exception 'invalid stream offset'; end if;
  if not exists(select 1 from stream_topics where id=p_topic and enabled) then raise exception 'topic disabled or unknown'; end if;
  if not exists(select 1 from regions where code=p_region and active) then raise exception 'region inactive or unknown'; end if;
  insert into stream_consumers(service_name,topic_id,region_code,partition_id,offset_value,lag_seconds,last_heartbeat)
  values(p_service,p_topic,p_region,p_partition,p_offset,p_lag,now())
  on conflict(service_name,topic_id,region_code,partition_id) do update set
    offset_value=greatest(stream_consumers.offset_value,excluded.offset_value),
    lag_seconds=excluded.lag_seconds,last_heartbeat=now();
end $$;
revoke all on function stream_commit_offset(text,text,text,int,bigint,int) from public,anon,authenticated;
grant execute on function stream_commit_offset(text,text,text,int,bigint,int) to service_role;

create or replace function correlation_close_window(
  p_window_id uuid,p_severity text,p_state jsonb
) returns void language plpgsql security definer set search_path=public as $$
begin
  update correlation_windows
  set closed=true,severity_max=p_severity,state=coalesce(p_state,'{}'::jsonb)
  where window_id=p_window_id and closed=false;
  if not found then raise exception 'correlation window not found or already closed'; end if;
end $$;
revoke all on function correlation_close_window(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function correlation_close_window(uuid,text,jsonb) to service_role;


-- ===== SOURCE sql/056_honeynet_mesh.sql =====
-- Cyclothone Honeynet Mesh catalog and placement control plane.
-- Builds on deception_artifacts/deception_triggers; no duplicate trigger ledger.

create table if not exists honey_mesh_templates (
  id text primary key,
  name text not null,
  deception_type text not null check (deception_type in ('honeyfile','fake_aws_key','fake_browser_cookie','fake_ssh_key','fake_wallet_seed','fake_admin_share','fake_service_account')),
  platform text[] not null default '{}',
  description text not null,
  default_paths jsonb not null default '{}'::jsonb,
  beacon_enabled boolean not null default false,
  severity text not null default 'critical' check (severity in ('high','critical')),
  enabled boolean not null default true
);

insert into honey_mesh_templates(id,name,deception_type,platform,description,default_paths,beacon_enabled) values
('aws_admin_keys','AWS admin credential marker','fake_aws_key',array['linux','windows','macos'],'Inert AWS-shaped canary credential.',
 '{"linux":["/root/.aws/credentials","/home/{user}/.aws/credentials"],"windows":["C:\\Users\\{user}\\.aws\\credentials"],"macos":["/Users/{user}/.aws/credentials"]}',false),
('ssh_root_key','SSH root key marker','fake_ssh_key',array['linux','macos'],'Inert SSH canary key.',
 '{"linux":["/root/.ssh/id_ed25519","/backup/.ssh/id_ed25519"],"macos":["/var/root/.ssh/id_ed25519"]}',false),
('prod_db_creds','Production DB credential marker','honeyfile',array['linux','windows'],'Inert database credential document.',
 '{"linux":["/root/.pgpass","/opt/app/.pgpass"],"windows":["C:\\Users\\{user}\\.pgpass"]}',false),
('ceo_email_mbox','CEO email marker','honeyfile',array['linux','windows','macos'],'Inert mailbox canary document.',
 '{"linux":["/home/{user}/Documents/ceo-mail.mbox"],"windows":["C:\\Users\\{user}\\Documents\\ceo.mbox"],"macos":["/Users/{user}/Documents/ceo.mbox"]}',true),
('swift_creds','SWIFT operator marker','honeyfile',array['windows'],'Inert banking credential document; never a working SWIFT credential.',
 '{"windows":["C:\\ProgramData\\SWIFT\\operator.ini"]}',true),
('crypto_wallet_seed','Crypto wallet marker','fake_wallet_seed',array['linux','windows','macos'],'Inert wallet canary; no funds and no usable seed.',
 '{"linux":["/home/{user}/.wallet/seed.txt","/root/wallet-seed.txt"],"windows":["C:\\Users\\{user}\\Documents\\seed.txt"],"macos":["/Users/{user}/Documents/seed.txt"]}',false),
('hr_payroll','Payroll marker','honeyfile',array['linux','windows'],'Inert payroll canary document.',
 '{"linux":["/srv/hr/payroll-canary.txt"],"windows":["C:\\Users\\{user}\\Documents\\payroll-canary.txt"]}',false),
('admin_share','Admin share marker','fake_admin_share',array['windows'],'Non-routable administrative share canary.',
 '{"windows":["C:\\Users\\{user}\\Desktop\\admin-backup\\creds.db"]}',false),
('k8s_service_token','Kubernetes token marker','fake_service_account',array['linux'],'Inert service-account canary; not accepted by any cluster.',
 '{"linux":["/var/run/secrets/kubernetes.io/serviceaccount/token"]}',true),
('vpn_config','VPN marker','honeyfile',array['linux','windows','macos'],'Inert VPN configuration canary.',
 '{"linux":["/etc/wireguard/canary.conf"],"windows":["C:\\Users\\{user}\\Documents\\vpn-canary.conf"],"macos":["/Users/{user}/Documents/vpn-canary.conf"]}',true)
on conflict(id) do update set name=excluded.name,deception_type=excluded.deception_type,platform=excluded.platform,
description=excluded.description,default_paths=excluded.default_paths,beacon_enabled=excluded.beacon_enabled,
severity=excluded.severity,enabled=excluded.enabled;

create table if not exists honey_mesh_assets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  template_id text not null references honey_mesh_templates(id),
  artifact_id uuid not null unique references deception_artifacts(id) on delete cascade,
  device_id uuid not null references devices(id) on delete cascade,
  path text not null,
  status text not null default 'planned' check (status in ('planned','deployed','tripped','removed','expired')),
  created_at timestamptz not null default now(),
  deployed_at timestamptz,
  unique(tenant_id,device_id,template_id,path)
);
create index if not exists idx_honey_mesh_assets_tenant on honey_mesh_assets(tenant_id,status);
create index if not exists idx_honey_mesh_assets_device on honey_mesh_assets(tenant_id,device_id,status);

alter table honey_mesh_templates enable row level security;
alter table honey_mesh_assets enable row level security;
create policy honey_mesh_templates_read on honey_mesh_templates for select to authenticated using (enabled=true);
create policy honey_mesh_assets_read on honey_mesh_assets for select to authenticated
  using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));
revoke insert,update,delete on honey_mesh_assets from anon,authenticated;
revoke all on function honey_mesh_coverage(uuid) from public,anon,authenticated;

create or replace function honey_mesh_coverage(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public as $$
  select jsonb_build_object(
    'assets',(select count(*) from honey_mesh_assets where tenant_id=p_tenant),
    'planned',(select count(*) from honey_mesh_assets where tenant_id=p_tenant and status='planned'),
    'deployed',(select count(*) from honey_mesh_assets where tenant_id=p_tenant and status='deployed'),
    'tripped',(select count(*) from honey_mesh_assets where tenant_id=p_tenant and status='tripped'),
    'devices',(select count(distinct device_id) from honey_mesh_assets where tenant_id=p_tenant)
  );
$$;
grant execute on function honey_mesh_coverage(uuid) to service_role;


-- ===== SOURCE sql/057_time_machine_foundation.sql =====
-- Cyclothone Time Machine durable snapshot-chain foundation.
-- Migration number intentionally follows existing 056 Honeynet Mesh.
-- No live migration is performed by this commit.

create table if not exists tm_snapshots (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    scope text not null check (scope in ('tenant','device','entity','case','account')),
    scope_ref text,
    snapshot_ts timestamptz not null,
    state jsonb not null,
    state_sha256 text not null check (state_sha256 ~ '^[0-9a-fA-F]{64}$'),
    event_count integer not null default 0 check (event_count >= 0),
    prev_snapshot uuid references tm_snapshots(id) on delete set null,
    chain_id uuid not null,
    chain_seq integer not null check (chain_seq >= 1),
    created_at timestamptz not null default now(),
    unique (tenant_id, scope, scope_ref, snapshot_ts)
);

create index if not exists idx_tm_snap_tenant_ts
    on tm_snapshots(tenant_id, snapshot_ts desc);
create index if not exists idx_tm_snap_scope
    on tm_snapshots(tenant_id, scope, scope_ref, snapshot_ts desc);
create index if not exists idx_tm_snap_chain
    on tm_snapshots(tenant_id, chain_id, chain_seq);

create table if not exists tm_deltas (
    id bigint generated by default as identity primary key,
    tenant_id uuid not null references tenants(id) on delete cascade,
    chain_id uuid not null,
    from_snapshot uuid references tm_snapshots(id) on delete set null,
    to_snapshot uuid references tm_snapshots(id) on delete set null,
    scope text not null check (scope in ('tenant','device','entity','case','account')),
    scope_ref text,
    delta_ts timestamptz not null,
    operations jsonb not null check (jsonb_typeof(operations) = 'array'),
    event_ids text[] not null default '{}',
    created_at timestamptz not null default now()
);

create index if not exists idx_tm_delta_chain
    on tm_deltas(tenant_id, chain_id, delta_ts);
create index if not exists idx_tm_delta_scope
    on tm_deltas(tenant_id, scope, scope_ref, delta_ts);
create index if not exists idx_tm_delta_tenant
    on tm_deltas(tenant_id, delta_ts desc);

create table if not exists tm_replays (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    scope text not null check (scope in ('tenant','device','entity','case','account')),
    scope_ref text,
    from_ts timestamptz not null,
    to_ts timestamptz not null check (to_ts > from_ts),
    step_ms integer not null default 1000 check (step_ms between 100 and 60000),
    status text not null default 'pending'
        check (status in ('pending','running','complete','failed')),
    frame_count integer check (frame_count is null or frame_count >= 0),
    frames_ref text,
    requested_by uuid references auth.users(id) on delete set null,
    error text,
    created_at timestamptz not null default now(),
    completed_at timestamptz
);

create index if not exists idx_tm_replay_tenant
    on tm_replays(tenant_id, created_at desc);

alter table tm_snapshots enable row level security;
alter table tm_deltas enable row level security;
alter table tm_replays enable row level security;

drop policy if exists tm_snapshots_tenant_select on tm_snapshots;
create policy tm_snapshots_tenant_select on tm_snapshots
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists tm_deltas_tenant_select on tm_deltas;
create policy tm_deltas_tenant_select on tm_deltas
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists tm_replays_tenant_select on tm_replays;
create policy tm_replays_tenant_select on tm_replays
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on tm_snapshots from anon, authenticated;
revoke all on tm_deltas from anon, authenticated;
revoke all on tm_replays from anon, authenticated;

-- Service-only atomic snapshot recording.
-- The advisory transaction lock serializes writers for one tenant/scope/ref/chain,
-- preventing duplicate chain_seq/prev_snapshot under concurrent workers.
create or replace function tm_record_snapshot(
    p_tenant uuid,
    p_scope text,
    p_scope_ref text,
    p_snapshot_ts timestamptz,
    p_state jsonb,
    p_state_sha text,
    p_event_count integer,
    p_chain_id uuid
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id uuid;
    v_prev uuid;
    v_seq integer;
    v_key text;
begin
    if p_tenant is null or not exists (
        select 1 from tenants where id = p_tenant
    ) then
        raise exception 'invalid tenant';
    end if;

    if p_scope not in ('tenant','device','entity','case','account') then
        raise exception 'invalid scope';
    end if;

    if p_snapshot_ts is null or p_state is null or p_chain_id is null then
        raise exception 'snapshot fields cannot be null';
    end if;

    if p_event_count is null or p_event_count < 0 then
        raise exception 'event_count must be nonnegative';
    end if;

    if p_state_sha is null or p_state_sha !~ '^[0-9a-fA-F]{64}$' then
        raise exception 'invalid state_sha256';
    end if;

    v_key := concat(
        p_tenant::text, ':', p_scope, ':',
        coalesce(p_scope_ref, ''), ':', p_chain_id::text
    );
    perform pg_advisory_xact_lock(hashtextextended(v_key, 0));

    select id, chain_seq
      into v_prev, v_seq
      from tm_snapshots
     where tenant_id = p_tenant
       and scope = p_scope
       and coalesce(scope_ref, '') = coalesce(p_scope_ref, '')
       and chain_id = p_chain_id
     order by snapshot_ts desc, created_at desc, id desc
     limit 1
     for update;

    v_seq := coalesce(v_seq, 0) + 1;

    insert into tm_snapshots (
        tenant_id, scope, scope_ref, snapshot_ts, state, state_sha256,
        event_count, prev_snapshot, chain_id, chain_seq
    )
    values (
        p_tenant, p_scope, p_scope_ref, p_snapshot_ts, p_state, lower(p_state_sha),
        p_event_count, v_prev, p_chain_id, v_seq
    )
    on conflict (tenant_id, scope, scope_ref, snapshot_ts)
    do update set
        state = excluded.state,
        state_sha256 = excluded.state_sha256,
        event_count = excluded.event_count
    returning id into v_id;

    return v_id;
end;
$$;

revoke all on function tm_record_snapshot(uuid,text,text,timestamptz,jsonb,text,integer,uuid)
    from public, anon, authenticated;
grant execute on function tm_record_snapshot(uuid,text,text,timestamptz,jsonb,text,integer,uuid)
    to service_role;

create or replace function tm_nearest_snapshot(
    p_tenant uuid,
    p_scope text,
    p_scope_ref text,
    p_ts timestamptz
)
returns uuid
language sql
stable
security definer
set search_path = public
as $$
    select id
      from tm_snapshots
     where tenant_id = p_tenant
       and scope = p_scope
       and coalesce(scope_ref, '') = coalesce(p_scope_ref, '')
       and snapshot_ts <= p_ts
     order by snapshot_ts desc, created_at desc, id desc
     limit 1;
$$;

revoke all on function tm_nearest_snapshot(uuid,text,text,timestamptz)
    from public, anon, authenticated;
grant execute on function tm_nearest_snapshot(uuid,text,text,timestamptz)
    to service_role;

comment on table tm_snapshots is 'Immutable time-machine state checkpoints; mutations occur only through service-role functions.';
comment on table tm_deltas is 'Tenant-scoped state deltas used to reconstruct checkpoints.';
comment on table tm_replays is 'Tenant-scoped replay job metadata; frame bundles remain externalized.';


-- ===== SOURCE sql/058_attack_dna_foundation.sql =====
-- sql/058_attack_dna_foundation.sql
-- Cyclothone Attack DNA: immutable evidence foundation.
-- This is an attribution evidence system, not a biological identification claim.

create table dna_traits (
    id text primary key,
    category text not null check (category in (
        'tooling','timing','targeting','language','crypto',
        'infrastructure','ttp','artifact','voice','visual','behavioral'
    )),
    name text not null,
    description text,
    dimension int not null check (dimension between 1 and 4096),
    weight real not null default 1.0 check (weight > 0 and weight <= 1),
    enabled boolean not null default true
);

insert into dna_traits (id,category,name,description,dimension,weight) values
('ttp.mitre_set','ttp','MITRE technique set','ATT&CK technique combination',128,0.90),
('tooling.malware_family','tooling','Malware family','Stable family/reuse indicators',64,0.85),
('tooling.tool_stack','tooling','Tool stack','Observed tooling combination',32,0.80),
('timing.beacon_interval','timing','Beacon interval','C2 callback timing distribution',16,0.75),
('timing.activity_hours','timing','Activity hours','UTC activity distribution',24,0.60),
('targeting.sector','targeting','Target sector','Observed sector targeting',32,0.70),
('targeting.geography','targeting','Target geography','Observed target geography',48,0.65),
('language.idioms','language','Language markers','Lexical/style markers',64,0.70),
('language.grammar_errors','language','Language error signature','Observed recurring linguistic patterns',32,0.55),
('crypto.address_pattern','crypto','Crypto address pattern','Address/reuse characteristics',32,0.80),
('crypto.ransom_note_style','crypto','Ransom note style','Document/template similarity',48,0.75),
('infrastructure.asn','infrastructure','ASN preference','Observed ASN reuse',32,0.70),
('infrastructure.domain_pattern','infrastructure','Domain pattern','Registration/DGA characteristics',48,0.70),
('infrastructure.cert_reuse','infrastructure','Certificate reuse','Certificate fingerprint overlap',32,0.75),
('artifact.file_metadata','artifact','File metadata','Compiler/linker/build metadata',48,0.80),
('artifact.mutex','artifact','Mutex names','Observed mutex reuse',32,0.70),
('voice.prosody','voice','Voice prosody','Extracted prosodic characteristics',48,0.65),
('visual.logo_phash','visual','Logo perceptual hash','Visual artifact similarity',32,0.60),
('behavioral.process_tree','behavioral','Process tree shape','Parent/child execution graph',128,0.85),
('behavioral.timing_signature','behavioral','Timing signature','Stage-to-stage delay pattern',64,0.75)
on conflict (id) do update set category=excluded.category,name=excluded.name,
description=excluded.description,dimension=excluded.dimension,weight=excluded.weight;

create table dna_signatures (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    kind text not null check (kind in ('actor','campaign','family','incident')),
    name text not null check (length(name) between 1 and 256),
    aliases text[] not null default '{}',
    vector real[] not null,
    vector_dim int not null check (vector_dim > 0),
    traits jsonb not null default '{}'::jsonb,
    trait_count int not null default 0 check (trait_count between 0 and 64),
    confidence real not null default 0.5 check (confidence between 0 and 1),
    origin_country text,
    motivation text,
    first_seen timestamptz,
    last_seen timestamptz,
    status text not null default 'unconfirmed'
        check (status in ('active','retired','merged','unconfirmed')),
    merged_into uuid references dna_signatures(id) on delete set null,
    extractor_version text not null default 'rules-v1',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check (vector_dim = coalesce(array_length(vector,1),0)),
    check (jsonb_typeof(traits) = 'object')
);
create index idx_dna_sig_tenant_status on dna_signatures(tenant_id,status);
create index idx_dna_sig_kind on dna_signatures(tenant_id,kind);

create table dna_fingerprints (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    source_kind text not null check (source_kind in (
        'detection','case','scam_report','darkweb','brand','physical'
    )),
    source_id text not null check (length(source_id) between 1 and 256),
    vector real[] not null,
    vector_dim int not null check (vector_dim > 0),
    traits jsonb not null default '{}'::jsonb,
    trait_ids text[] not null default '{}',
    confidence real not null check (confidence between 0 and 1),
    coverage real not null check (coverage between 0 and 1),
    extractor_version text not null default 'rules-v1',
    schema_hash text not null,
    observed_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    unique (tenant_id,source_kind,source_id),
    check (vector_dim = coalesce(array_length(vector,1),0)),
    check (jsonb_typeof(traits) = 'object')
);
create index idx_dna_fp_tenant_time on dna_fingerprints(tenant_id,observed_at desc);
create index idx_dna_fp_source on dna_fingerprints(tenant_id,source_kind,source_id);

create table dna_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    fingerprint_id uuid not null references dna_fingerprints(id) on delete cascade,
    signature_id uuid not null references dna_signatures(id) on delete cascade,
    cosine real not null check (cosine between 0 and 1),
    jaccard real not null check (jaccard between 0 and 1),
    trait_overlap int not null check (trait_overlap between 0 and 64),
    combined real not null check (combined between 0 and 1),
    verdict text not null check (verdict in ('attribution','partial','weak','none')),
    reasons jsonb not null default '[]'::jsonb,
    algorithm_version text not null default 'fusion-v1',
    case_id uuid references crime_cases(id) on delete set null,
    created_at timestamptz not null default now()
);
create index idx_dna_match_tenant_time on dna_matches(tenant_id,created_at desc);
create index idx_dna_match_sig_score on dna_matches(signature_id,combined desc);
create index idx_dna_match_fp on dna_matches(fingerprint_id);

create table dna_campaigns (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text,
    fingerprint_ids uuid[] not null default '{}',
    centroid real[] not null,
    centroid_dim int not null,
    cohesion real not null check (cohesion between 0 and 1),
    size int not null check (size >= 2),
    first_seen timestamptz not null,
    last_seen timestamptz not null,
    status text not null default 'active'
        check (status in ('active','closed','merged')),
    linked_case_ids uuid[] not null default '{}',
    algorithm_version text not null default 'cluster-v1',
    created_at timestamptz not null default now(),
    check (centroid_dim = coalesce(array_length(centroid,1),0)),
    check (last_seen >= first_seen)
);
create index idx_dna_campaign_tenant_time on dna_campaigns(tenant_id,last_seen desc);

alter table dna_signatures enable row level security;
alter table dna_fingerprints enable row level security;
alter table dna_matches enable row level security;
alter table dna_campaigns enable row level security;

create policy dna_sig_read on dna_signatures for select to authenticated
using (tenant_id is null or tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));
create policy dna_fp_read on dna_fingerprints for select to authenticated
using (tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));
create policy dna_match_read on dna_matches for select to authenticated
using (tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));
create policy dna_campaign_read on dna_campaigns for select to authenticated
using (tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));

revoke all on dna_traits,dna_signatures,dna_fingerprints,dna_matches,dna_campaigns
from anon,authenticated;

create or replace function dna_upsert_signature(
    p_tenant uuid, p_kind text, p_name text,
    p_vector real[], p_traits jsonb, p_trait_count int,
    p_confidence real, p_origin text, p_motivation text,
    p_extractor_version text default 'rules-v1'
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid;
begin
    if p_tenant is not null and not exists (select 1 from tenants where id=p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_vector is null or coalesce(array_length(p_vector,1),0) = 0 then
        raise exception 'signature vector required';
    end if;
    if p_trait_count is null or p_trait_count < 0 or p_trait_count > 64 then
        raise exception 'invalid trait count';
    end if;
    if p_traits is null or jsonb_typeof(p_traits) <> 'object' then
        raise exception 'traits must be an object';
    end if;
    if p_confidence is null or p_confidence < 0 or p_confidence > 1 then
        raise exception 'invalid confidence';
    end if;
    if exists (
        select 1 from unnest(p_vector) v
        where v is null or v <> v or v = 'Infinity'::real or v = '-Infinity'::real
    ) then
        raise exception 'non-finite vector value';
    end if;

    insert into dna_signatures(
        tenant_id,kind,name,vector,vector_dim,traits,trait_count,confidence,
        origin_country,motivation,extractor_version,first_seen,last_seen
    ) values (
        p_tenant,p_kind,p_name,p_vector,array_length(p_vector,1),p_traits,p_trait_count,
        p_confidence,p_origin,p_motivation,p_extractor_version,now(),now()
    ) returning id into v_id;
    return v_id;
end;
$$;

create or replace function dna_record_match(
    p_tenant uuid,p_fp uuid,p_sig uuid,p_cosine real,p_jaccard real,
    p_overlap int,p_combined real,p_verdict text,p_reasons jsonb,p_case uuid,
    p_algorithm_version text default 'fusion-v1'
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid; v_sig_tenant uuid; v_fp_tenant uuid; v_case_tenant uuid;
begin
    select tenant_id into v_fp_tenant from dna_fingerprints where id=p_fp;
    select tenant_id into v_sig_tenant from dna_signatures where id=p_sig;
    if v_fp_tenant is distinct from p_tenant then raise exception 'fingerprint tenant mismatch'; end if;
    if v_sig_tenant is not null and v_sig_tenant is distinct from p_tenant then raise exception 'signature tenant mismatch'; end if;
    if p_case is not null then
        select tenant_id into v_case_tenant from crime_cases where id=p_case;
        if v_case_tenant is distinct from p_tenant then raise exception 'case tenant mismatch'; end if;
    end if;
    if p_cosine is null or p_cosine < 0 or p_cosine > 1
       or p_jaccard is null or p_jaccard < 0 or p_jaccard > 1
       or p_combined is null or p_combined < 0 or p_combined > 1 then
        raise exception 'invalid DNA score';
    end if;
    insert into dna_matches(
        tenant_id,fingerprint_id,signature_id,cosine,jaccard,trait_overlap,
        combined,verdict,reasons,algorithm_version,case_id
    ) values (
        p_tenant,p_fp,p_sig,p_cosine,p_jaccard,p_overlap,p_combined,p_verdict,
        coalesce(p_reasons,'[]'::jsonb),p_algorithm_version,p_case
    ) returning id into v_id;
    return v_id;
end;
$$;

create or replace function dna_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public
as $$
select jsonb_build_object(
 'signatures',(select count(*) from dna_signatures where tenant_id is null or tenant_id=p_tenant),
 'fingerprints',(select count(*) from dna_fingerprints where tenant_id=p_tenant),
 'matches',(select count(*) from dna_matches where tenant_id=p_tenant),
 'attributions',(select count(*) from dna_matches where tenant_id=p_tenant and verdict='attribution'),
 'campaigns',(select count(*) from dna_campaigns where tenant_id=p_tenant and status='active')
);
$$;

revoke all on function dna_upsert_signature(uuid,text,text,real[],jsonb,int,real,text,text,text) from public,anon,authenticated;
revoke all on function dna_record_match(uuid,uuid,uuid,real,real,int,real,text,jsonb,uuid,text) from public,anon,authenticated;
revoke all on function dna_stats(uuid) from public,anon,authenticated;
grant execute on function dna_upsert_signature(uuid,text,text,real[],jsonb,int,real,text,text,text) to service_role;
grant execute on function dna_record_match(uuid,uuid,uuid,real,real,int,real,text,jsonb,uuid,text) to service_role;
grant execute on function dna_stats(uuid) to service_role;


-- ===== SOURCE sql/060_zk_compliance.sql =====
-- 060: zero-knowledge compliance foundation
create table zk_policies (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 name text not null check (length(name) between 1 and 120),
 predicate_kind text not null check (predicate_kind in ('count_gte','sum_gte','sum_lte','exists','rate_gte','coverage_gte')),
 predicate jsonb not null,
 regulator text,
 valid_from timestamptz,
 valid_until timestamptz,
 enabled boolean not null default true,
 created_at timestamptz not null default now(),
 check (valid_until is null or valid_from is null or valid_until > valid_from)
);
create index idx_zk_policy_tenant on zk_policies(tenant_id,enabled);
alter table zk_policies enable row level security;
create policy zk_policies_select on zk_policies for select to authenticated
 using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table zk_commitments (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 policy_id uuid references zk_policies(id) on delete set null,
 period_start timestamptz not null,
 period_end timestamptz not null,
 metric text not null check (length(metric) between 1 and 120),
 bucket bigint not null,
 commitment text not null check (commitment ~ '^[0-9a-f]{64}$'),
 blinding_ref text not null,
 leaf_index integer not null check (leaf_index >= 0),
 merkle_root text not null check (merkle_root ~ '^[0-9a-f]{64}$'),
 created_at timestamptz not null default now(),
 unique(tenant_id,policy_id,metric,period_start,leaf_index),
 check(period_end>period_start)
);
create index idx_zk_commit_tenant on zk_commitments(tenant_id,period_start desc);
create index idx_zk_commit_root on zk_commitments(merkle_root);
alter table zk_commitments enable row level security;
create policy zk_commitments_select on zk_commitments for select to authenticated
 using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table zk_proofs (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 policy_id uuid not null references zk_policies(id) on delete cascade,
 statement jsonb not null,
 merkle_root text not null check (merkle_root ~ '^[0-9a-f]{64}$'),
 proof_system text not null check (proof_system in ('merkle_commitment_v1')),
 proof_version text not null default '1',
 proof_payload jsonb not null,
 signature text not null,
 signer_kid text not null,
 status text not null default 'issued' check(status in ('issued','verified','rejected','expired')),
 verified_at timestamptz,
 verifier_id uuid references auth.users(id) on delete set null,
 verifier_note text,
 share_token text unique,
 share_expires timestamptz,
 created_at timestamptz not null default now()
);
create index idx_zk_proof_tenant on zk_proofs(tenant_id,created_at desc);
alter table zk_proofs enable row level security;
create policy zk_proofs_select on zk_proofs for select to authenticated
 using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table zk_verifications (
 id bigint generated always as identity primary key,
 proof_id uuid not null references zk_proofs(id) on delete cascade,
 verifier_ip inet,
 verifier_ua text,
 result boolean not null,
 reason text,
 verified_at timestamptz not null default now()
);
create index idx_zk_verify_proof on zk_verifications(proof_id,verified_at desc);
alter table zk_verifications enable row level security;
revoke all on zk_verifications from anon,authenticated;

revoke all on zk_policies,zk_commitments,zk_proofs from anon,authenticated;
grant select on zk_policies,zk_commitments,zk_proofs to authenticated;

create or replace function zk_record_commitment(
 p_tenant uuid,p_policy uuid,p_metric text,p_bucket bigint,p_commitment text,
 p_blinding_ref text,p_leaf_index integer,p_merkle_root text,
 p_period_start timestamptz,p_period_end timestamptz
) returns uuid language plpgsql security definer set search_path=public
as $$
declare v_id uuid;
begin
 if p_tenant is null or p_policy is null or p_leaf_index < 0 then raise exception 'invalid commitment'; end if;
 if not exists(select 1 from zk_policies where id=p_policy and tenant_id=p_tenant) then raise exception 'policy tenant mismatch'; end if;
 insert into zk_commitments(tenant_id,policy_id,metric,bucket,commitment,blinding_ref,leaf_index,merkle_root,period_start,period_end)
 values(p_tenant,p_policy,p_metric,p_bucket,lower(p_commitment),p_blinding_ref,p_leaf_index,lower(p_merkle_root),p_period_start,p_period_end)
 returning id into v_id;
 return v_id;
end $$;
revoke all on function zk_record_commitment(uuid,uuid,text,bigint,text,text,integer,text,timestamptz,timestamptz) from public;
grant execute on function zk_record_commitment(uuid,uuid,text,bigint,text,text,integer,text,timestamptz,timestamptz) to service_role;

create or replace function zk_stats(p_tenant uuid) returns jsonb language sql stable security definer set search_path=public
as $$
 select jsonb_build_object(
 'policies',(select count(*) from zk_policies where tenant_id=p_tenant and enabled),
 'commitments',(select count(*) from zk_commitments where tenant_id=p_tenant),
 'proofs',(select count(*) from zk_proofs where tenant_id=p_tenant),
 'verified',(select count(*) from zk_proofs where tenant_id=p_tenant and status='verified'),
 'rejected',(select count(*) from zk_proofs where tenant_id=p_tenant and status='rejected'));
$$;
revoke all on function zk_stats(uuid) from public;
grant execute on function zk_stats(uuid) to service_role;


-- ===== SOURCE sql/061_predictive.sql =====
-- sql/061_predictive.sql
-- Predictive Containment foundation. Service mutation boundary; tenant-derived reads.

create table if not exists attack_patterns (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    name text not null check (length(name) between 1 and 200),
    sequence text[] not null check (cardinality(sequence) between 1 and 32),
    occurrences bigint not null default 1 check (occurrences > 0),
    avg_hops real not null default 2.0 check (avg_hops >= 0 and avg_hops <= 32),
    avg_dwell_sec bigint not null default 300 check (avg_dwell_sec >= 0),
    success_rate real not null default 0.5 check (success_rate between 0 and 1),
    relation_weights jsonb not null default '{}'::jsonb,
    mitre_chain text[] not null default '{}',
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    unique (tenant_id, name)
);
create index if not exists idx_attack_patterns_tenant on attack_patterns(tenant_id, occurrences desc);

create table if not exists compromise_markers (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    source_kind text not null check (source_kind in ('detection','honeypot_touch','canary','ato','chain_hit','manual')),
    source_id text not null check (length(source_id) between 1 and 256),
    case_id uuid references crime_cases(id) on delete set null,
    node_id uuid,
    node_external text check (node_external is null or length(node_external) <= 512),
    node_type text not null check (length(node_type) between 1 and 64),
    confidence real not null default 0.8 check (confidence between 0 and 1),
    status text not null default 'active' check (status in ('active','contained','resolved','false_positive')),
    detected_at timestamptz not null default now(),
    resolved_at timestamptz,
    unique (tenant_id, source_kind, source_id, node_id)
);
create index if not exists idx_comp_marker_tenant on compromise_markers(tenant_id, status, detected_at desc);
create index if not exists idx_comp_marker_node on compromise_markers(tenant_id, node_id);

create table if not exists attack_predictions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    marker_id uuid not null references compromise_markers(id) on delete cascade,
    case_id uuid references crime_cases(id) on delete set null,
    model_kind text not null default 'graph_path_v1' check (length(model_kind) between 1 and 64),
    horizon_hops int not null default 3 check (horizon_hops between 1 and 5),
    top_targets int not null default 0 check (top_targets >= 0),
    confidence real not null default 0 check (confidence between 0 and 1),
    duration_ms int check (duration_ms is null or duration_ms >= 0),
    created_at timestamptz not null default now()
);
create index if not exists idx_predictions_tenant on attack_predictions(tenant_id, created_at desc);

create table if not exists predicted_targets (
    id uuid primary key default gen_random_uuid(),
    prediction_id uuid not null references attack_predictions(id) on delete cascade,
    tenant_id uuid not null references tenants(id) on delete cascade,
    node_id uuid not null,
    node_external text,
    node_type text not null,
    hops int not null check (hops between 1 and 5),
    prior_score real not null default 0 check (prior_score between 0 and 1),
    likelihood real not null default 0 check (likelihood between 0 and 1),
    impact real not null default 0 check (impact between 0 and 1),
    combined real not null default 0 check (combined between 0 and 1),
    path jsonb not null default '[]'::jsonb,
    preempted boolean not null default false,
    preempt_action text,
    attacker_arrived boolean,
    arrived_at timestamptz,
    created_at timestamptz not null default now()
);
create index if not exists idx_pt_prediction on predicted_targets(prediction_id, combined desc);
create index if not exists idx_pt_tenant on predicted_targets(tenant_id, preempted);
create index if not exists idx_pt_arrival on predicted_targets(tenant_id, attacker_arrived) where attacker_arrived = true;

create table if not exists preempt_actions (
    id bigint generated by default as identity primary key,
    tenant_id uuid not null references tenants(id) on delete cascade,
    predicted_target_id uuid not null references predicted_targets(id) on delete cascade,
    kind text not null check (kind in ('micro_segment','force_mfa','rotate_credentials','monitoring_boost','snapshot_now','block_lateral','isolate_preemptively','quarantine_preemptively')),
    status text not null default 'deployed' check (status in ('planned','dispatched','deployed','failed','rolled_back')),
    reversible boolean not null default true,
    rollback_args jsonb,
    reason text check (reason is null or length(reason) <= 2000),
    command_id uuid,
    created_at timestamptz not null default now()
);
create index if not exists idx_preempt_tenant on preempt_actions(tenant_id, created_at desc);

alter table attack_patterns enable row level security;
alter table compromise_markers enable row level security;
alter table attack_predictions enable row level security;
alter table predicted_targets enable row level security;
alter table preempt_actions enable row level security;

drop policy if exists attack_patterns_read on attack_patterns;
create policy attack_patterns_read on attack_patterns for select to authenticated
using (tenant_id is null or tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

drop policy if exists comp_marker_tenant on compromise_markers;
create policy comp_marker_tenant on compromise_markers for select to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

drop policy if exists predictions_tenant on attack_predictions;
create policy predictions_tenant on attack_predictions for select to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

drop policy if exists pt_tenant on predicted_targets;
create policy pt_tenant on predicted_targets for select to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

drop policy if exists preempt_tenant on preempt_actions;
create policy preempt_tenant on preempt_actions for select to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

revoke all on attack_patterns, compromise_markers, attack_predictions, predicted_targets, preempt_actions from anon, authenticated;

-- Revoke table access first; API routes use the service boundary.
revoke all on attack_patterns, compromise_markers, attack_predictions, predicted_targets, preempt_actions from anon, authenticated;

create or replace function predict_upsert_marker(
    p_tenant uuid, p_source_kind text, p_source_id text, p_case uuid,
    p_node uuid, p_node_ext text, p_node_type text, p_confidence real
) returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid;
begin
    if p_tenant is null or p_source_id is null or length(p_source_id) not between 1 and 256
       or p_node_type is null or length(p_node_type) not between 1 and 64
       or p_confidence is null or p_confidence < 0 or p_confidence > 1 then
        raise exception 'invalid predictive marker';
    end if;
    insert into compromise_markers
      (tenant_id, source_kind, source_id, case_id, node_id, node_external, node_type, confidence)
    values
      (p_tenant, p_source_kind, p_source_id, p_case, p_node, p_node_ext, p_node_type, p_confidence)
    on conflict (tenant_id, source_kind, source_id, node_id) do update
      set confidence = greatest(compromise_markers.confidence, excluded.confidence),
          detected_at = least(compromise_markers.detected_at, excluded.detected_at),
          status = case when compromise_markers.status = 'false_positive'
                        then 'active' else compromise_markers.status end,
          resolved_at = case when compromise_markers.status = 'false_positive'
                             then null else compromise_markers.resolved_at end
    returning id into v_id;
    return v_id;
end;
$$;

create or replace function predict_record_outcome(
    p_tenant uuid, p_target uuid, p_arrived boolean
) returns void
language plpgsql security definer set search_path = public
as $$
begin
    update predicted_targets
       set attacker_arrived = p_arrived,
           arrived_at = case when p_arrived then coalesce(arrived_at, now()) else arrived_at end
     where id = p_target and tenant_id = p_tenant;
    if not found then raise exception 'prediction target not found'; end if;
end;
$$;

create or replace function predict_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path = public
as $$
select jsonb_build_object(
 'active_compromises', (select count(*) from compromise_markers where tenant_id=p_tenant and status='active'),
 'predictions_24h', (select count(*) from attack_predictions where tenant_id=p_tenant and created_at > now()-interval '24 hours'),
 'preempted_targets', (select count(*) from predicted_targets where tenant_id=p_tenant and preempted),
 'attacker_arrivals', (select count(*) from predicted_targets where tenant_id=p_tenant and attacker_arrived),
 'preempted_arrivals', (select count(*) from predicted_targets where tenant_id=p_tenant and preempted and attacker_arrived),
 'hit_rate', coalesce(
   (select count(*)::numeric from predicted_targets where tenant_id=p_tenant and preempted and attacker_arrived) /
   nullif((select count(*)::numeric from predicted_targets where tenant_id=p_tenant and preempted),0), 0)
);
$$;

revoke all on function predict_upsert_marker(uuid,text,text,uuid,uuid,text,text,real) from public;
revoke all on function predict_record_outcome(uuid,uuid,boolean) from public;
revoke all on function predict_stats(uuid) from public;
grant execute on function predict_upsert_marker(uuid,text,text,uuid,uuid,text,text,real) to service_role;
grant execute on function predict_record_outcome(uuid,uuid,boolean) to service_role;
grant execute on function predict_stats(uuid) to service_role;


-- ===== SOURCE sql/062_bounty.sql =====
-- 062: threat bounty network, hardened production foundation
create table bounty_researchers (
 id uuid primary key default gen_random_uuid(),
 user_id uuid unique references auth.users(id) on delete set null,
 handle text not null unique check (handle ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$'),
 display_name text check (display_name is null or length(display_name) between 1 and 120),
 country text check (country is null or country ~ '^[A-Z]{2}$'),
 tier text not null default 'bronze' check (tier in ('bronze','silver','gold','platinum')),
 vetted boolean not null default false, vetted_by uuid references auth.users(id) on delete set null, vetted_at timestamptz,
 reputation numeric(5,4) not null default 0.5000 check (reputation between 0 and 1),
 submissions_total integer not null default 0 check (submissions_total >= 0),
 accepted_total integer not null default 0 check (accepted_total >= 0), rejected_total integer not null default 0 check (rejected_total >= 0),
 paid_total_usd numeric(20,2) not null default 0 check (paid_total_usd >= 0),
 payout_method text check (payout_method in ('usdc','usdt','wire','ach','sepa','mobile_money','paypal')),
 payout_ref text, tax_country text check (tax_country is null or tax_country ~ '^[A-Z]{2}$'), tax_id text,
 status text not null default 'active' check (status in ('active','suspended','banned')), created_at timestamptz not null default now()
);
create index idx_bounty_res_status on bounty_researchers(status,tier);
create index idx_bounty_res_reputation on bounty_researchers(reputation desc);

create table bounty_campaigns (
 id uuid primary key default gen_random_uuid(), tenant_id uuid references tenants(id) on delete cascade,
 name text not null check (length(name) between 1 and 200), description text check (description is null or length(description)<=10000),
 category text not null check (category in ('ioc','rule','vulnerability','malware_sample','attribution','threat_report','tool','research')),
 acceptance jsonb not null default '{}'::jsonb, payout_tiers jsonb not null default '{}'::jsonb,
 currency text not null default 'USD' check (currency ~ '^[A-Z]{3}$'),
 budget_total numeric(20,2) not null check (budget_total>0), budget_spent numeric(20,2) not null default 0 check (budget_spent>=0 and budget_spent<=budget_total),
 starts_at timestamptz not null default now(), ends_at timestamptz, enabled boolean not null default true, created_at timestamptz not null default now(),
 check (ends_at is null or ends_at>starts_at), check (jsonb_typeof(acceptance)='object'), check (jsonb_typeof(payout_tiers)='object')
);
create index idx_bounty_camp_tenant on bounty_campaigns(tenant_id,enabled);
create index idx_bounty_camp_category on bounty_campaigns(category,enabled);
alter table bounty_campaigns enable row level security;
create policy bounty_campaigns_select on bounty_campaigns for select to authenticated using (tenant_id is null or tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table bounty_submissions (
 id uuid primary key default gen_random_uuid(), researcher_id uuid not null references bounty_researchers(id) on delete restrict,
 campaign_id uuid not null references bounty_campaigns(id) on delete restrict, title text not null check(length(title) between 3 and 400),
 body text not null check(length(body) between 1 and 20000), artifacts jsonb not null default '[]'::jsonb check(jsonb_typeof(artifacts)='array'),
 content_hash text not null check(content_hash ~ '^[0-9a-f]{64}$'), auto_verdict text check(auto_verdict in ('accept','reject','peer_review','curator_review')),
 auto_score numeric(6,5) check(auto_score is null or auto_score between 0 and 1), auto_reasons jsonb not null default '[]'::jsonb,
 verdict text not null default 'pending' check(verdict in ('pending','accept','reject','duplicate','malicious')),
 verdict_by uuid references auth.users(id) on delete set null, verdict_at timestamptz, verdict_reason text,
 severity text check(severity in ('low','medium','high','critical')), payout_amount numeric(20,2) check(payout_amount is null or payout_amount>=0),
 payout_status text not null default 'not_owed' check(payout_status in ('not_owed','owed','processing','paid','failed')),
 payout_tx text, payout_at timestamptz, block_ref text, created_at timestamptz not null default now(),
 unique(campaign_id,content_hash)
);
create index idx_bounty_sub_res on bounty_submissions(researcher_id,created_at desc);
create index idx_bounty_sub_camp on bounty_submissions(campaign_id,verdict,created_at desc);
create index idx_bounty_sub_payout on bounty_submissions(payout_status,created_at) where payout_status in ('owed','processing');

create table bounty_verifications (
 id bigint generated always as identity primary key, submission_id uuid not null references bounty_submissions(id) on delete cascade,
 verifier_id uuid not null references bounty_researchers(id) on delete restrict,
 role text not null check(role in ('peer','curator','adversarial')), verdict text not null check(verdict in ('accept','reject','needs_more')),
 score numeric(6,5) not null default 0.50000 check(score between 0 and 1), comment text check(comment is null or length(comment)<=5000),
 created_at timestamptz not null default now(), unique(submission_id,verifier_id,role)
);
create index idx_bounty_verif_sub on bounty_verifications(submission_id,created_at desc);

create table bounty_payouts (
 id uuid primary key default gen_random_uuid(), researcher_id uuid not null references bounty_researchers(id) on delete restrict,
 submission_id uuid unique references bounty_submissions(id) on delete set null, amount numeric(20,2) not null check(amount>0),
 currency text not null check(currency ~ '^[A-Z]{3}$'), method text not null check(method in ('usdc','usdt','wire','ach','sepa','mobile_money','paypal')),
 status text not null default 'queued' check(status in ('queued','processing','sent','confirmed','failed')),
 provider text, idempotency_key text not null unique, attempts integer not null default 0 check(attempts>=0 and attempts<=20), provider_ref text, tx_hash text, error text, created_at timestamptz not null default now(), sent_at timestamptz, confirmed_at timestamptz,
 check((status in ('sent','confirmed') and provider_ref is not null) or status not in ('sent','confirmed')),
 check(status <> 'confirmed' or confirmed_at is not null)
);
create index idx_bounty_payout_res on bounty_payouts(researcher_id,created_at desc);
create index idx_bounty_payout_status on bounty_payouts(status,created_at);

alter table bounty_researchers enable row level security;
alter table bounty_submissions enable row level security;
alter table bounty_verifications enable row level security;
alter table bounty_payouts enable row level security;
revoke all on bounty_researchers,bounty_submissions,bounty_verifications,bounty_payouts,bounty_campaigns from anon,authenticated;

create or replace function bounty_register_researcher(p_user uuid,p_handle text,p_display_name text,p_country text,payout_method text,payout_ref text)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 if p_user is null or not exists(select 1 from auth.users where id=p_user) then raise exception 'user required'; end if;
 if p_handle is null or p_handle !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$' then raise exception 'invalid handle'; end if;
 if payout_method is not null and payout_method not in ('usdc','usdt','wire','ach','sepa','mobile_money','paypal') then raise exception 'invalid payout method'; end if;
 insert into bounty_researchers(user_id,handle,display_name,country,payout_method,payout_ref)
 values(p_user,p_handle,p_display_name,p_country,payout_method,payout_ref) returning id into v_id; return v_id;
end $$;
revoke all on function bounty_register_researcher(uuid,text,text,text,text,text) from public;
grant execute on function bounty_register_researcher(uuid,text,text,text,text,text) to service_role;

create or replace function bounty_submit(p_researcher uuid,p_campaign uuid,p_title text,p_body text,p_artifacts jsonb,p_content_hash text,p_auto_verdict text,p_auto_score real,p_auto_reasons jsonb)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid; v_status text; v_enabled boolean; v_start timestamptz; v_end timestamptz;
begin
 select r.status,c.enabled,c.starts_at,c.ends_at into v_status,v_enabled,v_start,v_end from bounty_researchers r cross join bounty_campaigns c where r.id=p_researcher and c.id=p_campaign;
 if v_status is null or v_status<>'active' then raise exception 'researcher not active'; end if;
 if coalesce(v_enabled,false)=false or now()<v_start or (v_end is not null and now()>=v_end) then raise exception 'campaign not active'; end if;
 insert into bounty_submissions(researcher_id,campaign_id,title,body,artifacts,content_hash,auto_verdict,auto_score,auto_reasons)
 values(p_researcher,p_campaign,left(p_title,400),left(p_body,20000),p_artifacts,lower(p_content_hash),p_auto_verdict,p_auto_score,p_auto_reasons) returning id into v_id;
 update bounty_researchers set submissions_total=submissions_total+1 where id=p_researcher; return v_id;
exception when unique_violation then raise exception 'duplicate submission'; end $$;
revoke all on function bounty_submit(uuid,uuid,text,text,jsonb,text,text,real,jsonb) from public;
grant execute on function bounty_submit(uuid,uuid,text,text,jsonb,text,text,real,jsonb) to service_role;

create or replace function bounty_decide(p_submission uuid,p_verdict text,p_severity text,p_payout numeric,p_verdict_by uuid,p_reason text,p_block_ref text default null)
returns void language plpgsql security definer set search_path=public as $$
declare v_researcher uuid; v_campaign uuid; v_old text; v_budget numeric; v_amount numeric;
begin
 if p_verdict not in ('accept','reject','duplicate','malicious') then raise exception 'invalid verdict'; end if;
 if p_verdict='accept' and p_severity not in ('low','medium','high','critical') then raise exception 'severity required'; end if;
 if p_verdict='accept' and (p_block_ref is null or length(trim(p_block_ref))=0) then raise exception 'confirmed block reference required'; end if;
 select researcher_id,campaign_id,verdict into v_researcher,v_campaign,v_old from bounty_submissions where id=p_submission for update;
 if v_researcher is null then raise exception 'submission not found'; end if;
 if v_old<>'pending' then raise exception 'submission already decided'; end if;
 select budget_total-budget_spent into v_budget from bounty_campaigns where id=v_campaign for update;
 v_amount:=case when p_verdict='accept' then greatest(coalesce(p_payout,0),0) else 0 end;
 if v_amount>v_budget then raise exception 'campaign budget exceeded'; end if;
 update bounty_submissions set verdict=p_verdict,severity=case when p_verdict='accept' then p_severity else null end,
 payout_amount=case when p_verdict='accept' then v_amount else null end,payout_status=case when p_verdict='accept' and v_amount>0 then 'owed' else 'not_owed' end,
 verdict_by=p_verdict_by,verdict_at=now(),verdict_reason=left(p_reason,1000),block_ref=left(p_block_ref,500) where id=p_submission;
 if p_verdict='accept' then
  update bounty_campaigns set budget_spent=budget_spent+v_amount where id=v_campaign;
  update bounty_researchers set accepted_total=accepted_total+1,reputation=least(1,reputation+0.02) where id=v_researcher;
 else
  update bounty_researchers set rejected_total=rejected_total+1,reputation=greatest(0,reputation-0.03) where id=v_researcher;
 end if;
end $$;
revoke all on function bounty_decide(uuid,text,text,numeric,uuid,text,text) from public;
grant execute on function bounty_decide(uuid,text,text,numeric,uuid,text,text) to service_role;

create or replace function bounty_claim_payouts(p_limit integer default 50)
returns setof bounty_payouts language plpgsql security definer set search_path=public as $$
begin
 if p_limit<1 or p_limit>200 then raise exception 'invalid payout batch'; end if;
 return query
 with candidates as (
  select s.id from bounty_submissions s join bounty_researchers r on r.id=s.researcher_id join bounty_campaigns c on c.id=s.campaign_id where s.payout_status='owed' and s.payout_amount>0 and r.payout_method is not null and c.enabled and now() >= c.starts_at and (c.ends_at is null or now() < c.ends_at) order by s.created_at for update of s skip locked limit p_limit
 ), claimed as (
  update bounty_submissions s set payout_status='processing' from candidates c where s.id=c.id returning s.*
 )
 insert into bounty_payouts(researcher_id,submission_id,amount,currency,method,status,provider,idempotency_key,attempts)
 select s.researcher_id,s.id,s.payout_amount,c.currency,r.payout_method,'processing',null,md5('cyclothone:bounty:payout:'||s.id::text),1
 from claimed s join bounty_campaigns c on c.id=s.campaign_id join bounty_researchers r on r.id=s.researcher_id
 where r.payout_method is not null
 on conflict(submission_id) do update set status='processing',attempts=bounty_payouts.attempts+1,error=null,provider_ref=null,tx_hash=null,sent_at=null,confirmed_at=null
 where bounty_payouts.status in ('queued','failed') and bounty_payouts.attempts < 20
 returning *;
end $$;
revoke all on function bounty_claim_payouts(integer) from public;
grant execute on function bounty_claim_payouts(integer) to service_role;

create or replace function bounty_mark_payout(p_payout uuid,p_status text,p_provider_ref text default null,p_tx_hash text default null,p_error text default null)
returns void language plpgsql security definer set search_path=public as $$
declare v_submission uuid; v_researcher uuid; v_amount numeric;
begin
 if p_status not in ('sent','confirmed','failed') then raise exception 'invalid payout transition'; end if;
 select submission_id,researcher_id,amount into v_submission,v_researcher,v_amount from bounty_payouts where id=p_payout for update;
 if v_submission is null then raise exception 'payout not found'; end if;
 if p_status in ('sent','confirmed') and coalesce(p_provider_ref,p_tx_hash) is null then raise exception 'provider reference required'; end if;
 if (select status from bounty_payouts where id=p_payout)='confirmed' then raise exception 'payout already confirmed'; end if;
 if (select status from bounty_payouts where id=p_payout)='sent' and p_status not in ('confirmed','sent') then raise exception 'invalid payout transition'; end if;
 update bounty_payouts set status=p_status,provider_ref=coalesce(p_provider_ref,provider_ref),tx_hash=coalesce(p_tx_hash,tx_hash),
 error=case when p_status='failed' then left(p_error,500) else null end,sent_at=case when p_status in ('sent','confirmed') then coalesce(sent_at,now()) else sent_at end,
 confirmed_at=case when p_status='confirmed' then coalesce(confirmed_at,now()) else confirmed_at end where id=p_payout;
 if p_status='confirmed' then
  update bounty_submissions set payout_status='paid',payout_tx=coalesce(p_tx_hash,p_provider_ref),payout_at=coalesce(payout_at,now()) where id=v_submission and payout_status='processing';
  update bounty_researchers set paid_total_usd=paid_total_usd+v_amount where id=v_researcher;
 elsif p_status='failed' then update bounty_submissions set payout_status='owed' where id=v_submission and payout_status='processing'; end if;
end $$;
revoke all on function bounty_mark_payout(uuid,text,text,text,text) from public;
grant execute on function bounty_mark_payout(uuid,text,text,text,text) to service_role;

create or replace function bounty_stats(p_tenant uuid) returns jsonb language sql stable security definer set search_path=public as $$
select jsonb_build_object(
'researchers_total',(select count(*) from bounty_researchers where status='active'),
'researchers_vetted',(select count(*) from bounty_researchers where status='active' and vetted),
'campaigns_active',(select count(*) from bounty_campaigns where enabled and (tenant_id is null or tenant_id=p_tenant)),
'submissions_30d',(select count(*) from bounty_submissions s join bounty_campaigns c on c.id=s.campaign_id where s.created_at>now()-interval '30 days' and (c.tenant_id is null or c.tenant_id=p_tenant)),
'accepted_30d',(select count(*) from bounty_submissions s join bounty_campaigns c on c.id=s.campaign_id where s.verdict='accept' and s.created_at>now()-interval '30 days' and (c.tenant_id is null or c.tenant_id=p_tenant)),
'paid_total',(select coalesce(sum(p.amount),0) from bounty_payouts p join bounty_submissions s on s.id=p.submission_id join bounty_campaigns c on c.id=s.campaign_id where p.status in ('sent','confirmed') and (c.tenant_id is null or c.tenant_id=p_tenant)),
'owed_total',(select coalesce(sum(s.payout_amount),0) from bounty_submissions s join bounty_campaigns c on c.id=s.campaign_id where s.payout_status in ('owed','processing') and (c.tenant_id is null or c.tenant_id=p_tenant)));
$$;
revoke all on function bounty_stats(uuid) from public;
grant execute on function bounty_stats(uuid) to service_role;


-- ===== SOURCE sql/063_fusion.sql =====
-- Cyclothone Physical-Cyber Fusion foundation.
-- Migration slot 063 is unused on this development branch.
-- Service mutations are privileged; tenant identity is validated server-side.

create table if not exists public.fusion_edges (
    id bigserial primary key,
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    src_kind text not null check (src_kind in
        ('person','device','badge','camera','sensor','door','account','session','vehicle','ot_device')),
    src_id text not null check (length(src_id) between 1 and 256),
    dst_kind text not null check (dst_kind in
        ('person','device','badge','camera','sensor','door','account','session','vehicle','ot_device')),
    dst_id text not null check (length(dst_id) between 1 and 256),
    relation text not null check (relation in
        ('entered','exited','observed_by','opened','authenticated','operated','accompanied','was_near','triggered','unlocked')),
    weight real not null default 1.0 check (weight <> 'NaN'::real and abs(weight) <> 'Infinity'::real and weight > 0 and weight <= 1000000),
    confidence real not null default 0.8 check (confidence <> 'NaN'::real and abs(confidence) <> 'Infinity'::real and confidence >= 0 and confidence <= 1),
    site_id uuid references public.physical_sites(id) on delete set null,
    ts timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object')
);

create index if not exists idx_fusion_edges_src on public.fusion_edges(tenant_id,src_kind,src_id,ts desc);
create index if not exists idx_fusion_edges_dst on public.fusion_edges(tenant_id,dst_kind,dst_id,ts desc);
create index if not exists idx_fusion_edges_ts on public.fusion_edges(tenant_id,ts desc);

create table if not exists public.fusion_correlations (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    kind text not null check (kind in
        ('impossible_travel','dual_presence','orphan_session','shadow_access','tailgating','badge_clone',
         'camera_conflict','door_anomaly','ot_cross_access','badge_revoked_use','schedule_violation')),
    severity text not null default 'high' check (severity in ('medium','high','critical')),
    entity_kind text not null check (entity_kind in
        ('person','device','badge','camera','sensor','door','account','session','vehicle','ot_device')),
    entity_id text not null check (length(entity_id) between 1 and 256),
    evidence jsonb not null default '[]'::jsonb check (jsonb_typeof(evidence) = 'array'),
    distance_km real check (distance_km is null or (distance_km <> 'NaN'::real and abs(distance_km) <> 'Infinity'::real and distance_km >= 0)),
    elapsed_seconds integer check (elapsed_seconds is null or elapsed_seconds >= 0),
    status text not null default 'new'
        check (status in ('new','acknowledged','investigating','resolved','false_positive')),
    case_id uuid references public.crime_cases(id) on delete set null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    check (last_seen >= first_seen)
);

create index if not exists idx_fusion_corr_tenant on public.fusion_correlations(tenant_id,first_seen desc);
create index if not exists idx_fusion_corr_status on public.fusion_correlations(tenant_id,status);
create index if not exists idx_fusion_corr_entity on public.fusion_correlations(tenant_id,kind,entity_kind,entity_id,first_seen desc);

alter table public.fusion_edges enable row level security;
alter table public.fusion_correlations enable row level security;

drop policy if exists fusion_edges_tenant on public.fusion_edges;
create policy fusion_edges_tenant on public.fusion_edges
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

drop policy if exists fusion_corr_tenant on public.fusion_correlations;
create policy fusion_corr_tenant on public.fusion_correlations
    for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on public.fusion_edges from anon, authenticated;
revoke all on public.fusion_correlations from anon, authenticated;
grant select on public.fusion_edges, public.fusion_correlations to authenticated;

create or replace function public.fusion_upsert_edge(
    p_tenant uuid, p_src_kind text, p_src_id text,
    p_dst_kind text, p_dst_id text, p_relation text,
    p_site uuid, p_confidence real, p_metadata jsonb, p_ts timestamptz default now()
) returns bigint
language plpgsql security definer set search_path = public
as $$
declare v_id bigint;
begin
    if not exists (select 1 from public.tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_src_id is null or length(p_src_id) not between 1 and 256
       or p_dst_id is null or length(p_dst_id) not between 1 and 256 then
        raise exception 'invalid entity id';
    end if;
    if p_confidence is null or p_confidence = 'NaN'::real or abs(p_confidence) = 'Infinity'::real or p_confidence < 0 or p_confidence > 1 then
        raise exception 'invalid confidence';
    end if;
    if p_metadata is null or jsonb_typeof(p_metadata) <> 'object' then
        raise exception 'metadata must be an object';
    end if;

    -- A repeated relationship gets a bounded confidence-weighted recurrence score.
    insert into public.fusion_edges
        (tenant_id,src_kind,src_id,dst_kind,dst_id,relation,site_id,weight,confidence,metadata,ts)
    values
        (p_tenant,p_src_kind,p_src_id,p_dst_kind,p_dst_id,p_relation,p_site,1.0,p_confidence,p_metadata,p_ts)
    returning id into v_id;
    return v_id;
end;
$$;

create or replace function public.fusion_open_correlation(
    p_tenant uuid, p_kind text, p_severity text,
    p_entity_kind text, p_entity_id text, p_evidence jsonb,
    p_distance_km real default null, p_elapsed_seconds integer default null,
    p_seen_at timestamptz default now()
) returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid;
begin
    if not exists (select 1 from public.tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_evidence is null or jsonb_typeof(p_evidence) <> 'array' or jsonb_array_length(p_evidence) > 64 then
        raise exception 'invalid evidence';
    end if;

    perform pg_advisory_xact_lock(hashtextextended(
        p_tenant::text || ':' || p_kind || ':' || p_entity_kind || ':' || p_entity_id, 0));

    select id into v_id
      from public.fusion_correlations
     where tenant_id = p_tenant
       and kind = p_kind
       and entity_kind = p_entity_kind
       and entity_id = p_entity_id
       and first_seen > p_seen_at - interval '1 hour'
       and status not in ('resolved','false_positive')
     order by first_seen desc
     limit 1
     for update;

    if v_id is not null then
        update public.fusion_correlations
           set last_seen = greatest(last_seen,p_seen_at),
               severity = case
                   when severity = 'critical' or p_severity = 'critical' then 'critical'
                   when severity = 'high' or p_severity = 'high' then 'high'
                   else 'medium' end,
               evidence = (
                   select coalesce(jsonb_agg(x.value order by x.ord), '[]'::jsonb)
                   from (
                       select value, ord from jsonb_array_elements(evidence) with ordinality
                       union all
                       select value, ord + coalesce((select max(z.ord) from jsonb_array_elements(evidence) with ordinality z),0)
                       from jsonb_array_elements(p_evidence) with ordinality
                   ) x
                   limit 64
               )
         where id = v_id;
        return v_id;
    end if;

    insert into public.fusion_correlations
        (tenant_id,kind,severity,entity_kind,entity_id,evidence,distance_km,elapsed_seconds,first_seen,last_seen)
    values
        (p_tenant,p_kind,p_severity,p_entity_kind,p_entity_id,p_evidence,p_distance_km,p_elapsed_seconds,p_seen_at,p_seen_at)
    returning id into v_id;
    return v_id;
end;
$$;

create or replace function public.fusion_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path = public
as $$
    select jsonb_build_object(
      'edges_24h',(select count(*) from public.fusion_edges where tenant_id=p_tenant and ts>now()-interval '24 hours'),
      'correlations_30d',(select count(*) from public.fusion_correlations where tenant_id=p_tenant and first_seen>now()-interval '30 days'),
      'open_correlations',(select count(*) from public.fusion_correlations where tenant_id=p_tenant and status in ('new','acknowledged','investigating')),
      'critical_open',(select count(*) from public.fusion_correlations where tenant_id=p_tenant and status in ('new','acknowledged','investigating') and severity='critical')
    );
$$;

revoke all on function public.fusion_upsert_edge(uuid,text,text,text,text,text,uuid,real,jsonb,timestamptz) from public;
revoke all on function public.fusion_open_correlation(uuid,text,text,text,text,jsonb,real,integer,timestamptz) from public;
revoke all on function public.fusion_stats(uuid) from public;
grant execute on function public.fusion_upsert_edge(uuid,text,text,text,text,text,uuid,real,jsonb,timestamptz) to service_role;
grant execute on function public.fusion_open_correlation(uuid,text,text,text,text,jsonb,real,integer,timestamptz) to service_role;
grant execute on function public.fusion_stats(uuid) to service_role;


-- ===== SOURCE sql/064_digital_twin.sql =====
-- Digital Twin foundation: tenant-scoped topology + durable simulation records.
-- Simulations are advisory only; this migration grants no execution authority.

create table twin_nodes (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    node_type text not null check (node_type in (
        'device','user','process','file','network','service','database','credential',
        'endpoint','container','ot_device','camera','door','account','session'
    )),
    external_id text not null check (length(btrim(external_id)) between 1 and 512),
    label text check (label is null or length(label) <= 512),
    criticality real not null default 0.5 check (criticality >= 0 and criticality <= 1),
    attributes jsonb not null default '{}'::jsonb check (jsonb_typeof(attributes) = 'object'),
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    unique (tenant_id, node_type, external_id)
);

create index idx_twin_nodes_tenant_type on twin_nodes(tenant_id, node_type, id);
create index idx_twin_nodes_tenant_ext on twin_nodes(tenant_id, external_id);

create table twin_edges (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    source_id uuid not null references twin_nodes(id) on delete cascade,
    target_id uuid not null references twin_nodes(id) on delete cascade,
    relation text not null check (relation in (
        'runs','runs_on','connects_to','reads','writes','executes','authenticates',
        'owns','depends_on','hosts','manages','trusts','controls'
    )),
    weight real not null default 1.0 check (weight >= 0 and weight <= 10),
    criticality real not null default 0.5 check (criticality >= 0 and criticality <= 1),
    last_seen timestamptz not null default now(),
    unique (source_id, target_id, relation),
    check (source_id <> target_id)
);

create index idx_twin_edges_tenant_src on twin_edges(tenant_id, source_id, relation);
create index idx_twin_edges_tenant_dst on twin_edges(tenant_id, target_id, relation);

create table twin_simulations (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    action text not null check (action in (
        'isolate_host','kill_process','quarantine_file','disable_account',
        'force_logout','block_hash','block_ip'
    )),
    target_node_id uuid not null references twin_nodes(id) on delete cascade,
    args jsonb not null default '{}'::jsonb check (jsonb_typeof(args) = 'object'),
    requested_by uuid references auth.users(id) on delete set null,
    status text not null default 'pending'
        check (status in ('pending','running','complete','failed')),
    impact_score real check (impact_score is null or (impact_score >= 0 and impact_score <= 1)),
    cascade_size integer check (cascade_size is null or (cascade_size >= 0 and cascade_size <= 1000000)),
    affected_nodes jsonb not null default '[]'::jsonb
        check (jsonb_typeof(affected_nodes) = 'array' and jsonb_array_length(affected_nodes) <= 500),
    critical_impact jsonb not null default '[]'::jsonb
        check (jsonb_typeof(critical_impact) = 'array' and jsonb_array_length(critical_impact) <= 100),
    recommendation text check (recommendation is null or length(recommendation) <= 2000),
    duration_ms integer check (duration_ms is null or duration_ms >= 0),
    created_at timestamptz not null default now()
);

create index idx_twin_sim_tenant_created on twin_simulations(tenant_id, created_at desc);
create index idx_twin_sim_tenant_target on twin_simulations(tenant_id, target_node_id);

alter table twin_nodes enable row level security;
alter table twin_edges enable row level security;
alter table twin_simulations enable row level security;

create policy twin_nodes_select on twin_nodes
    for select to authenticated
    using ((select auth.jwt() ->> 'tenant_id')::uuid = tenant_id);
create policy twin_edges_select on twin_edges
    for select to authenticated
    using ((select auth.jwt() ->> 'tenant_id')::uuid = tenant_id);
create policy twin_simulations_select on twin_simulations
    for select to authenticated
    using ((select auth.jwt() ->> 'tenant_id')::uuid = tenant_id);

create or replace function twin_validate_edge_tenant()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    v_source_tenant uuid;
    v_target_tenant uuid;
begin
    select tenant_id into v_source_tenant from twin_nodes where id = new.source_id;
    select tenant_id into v_target_tenant from twin_nodes where id = new.target_id;
    if v_source_tenant is null or v_target_tenant is null
       or v_source_tenant <> new.tenant_id or v_target_tenant <> new.tenant_id then
        raise exception 'twin edge tenant mismatch';
    end if;
    return new;
end;
$$;

drop trigger if exists trg_twin_validate_edge_tenant on twin_edges;
create trigger trg_twin_validate_edge_tenant
before insert or update on twin_edges
for each row execute function twin_validate_edge_tenant();

revoke all on table twin_nodes, twin_edges, twin_simulations from public, anon, authenticated;
grant select, insert, update on twin_nodes to service_role;
grant select, insert, update on twin_edges to service_role;
grant select, insert, update on twin_simulations to service_role;
revoke all on function twin_validate_edge_tenant() from public, anon, authenticated;

create or replace function twin_upsert_node(
    p_tenant uuid, p_node_type text, p_external_id text,
    p_label text, p_criticality real, p_attributes jsonb
)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid;
begin
    if p_tenant is null or not exists (select 1 from tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_external_id is null or length(btrim(p_external_id)) = 0 or length(p_external_id) > 512 then
        raise exception 'invalid external_id';
    end if;
    if p_attributes is null or jsonb_typeof(p_attributes) <> 'object' then
        raise exception 'attributes must be a JSON object';
    end if;
    if p_criticality is null or p_criticality < 0 or p_criticality > 1 then
        raise exception 'criticality must be between 0 and 1';
    end if;
    insert into twin_nodes(tenant_id,node_type,external_id,label,criticality,attributes)
    values(p_tenant,btrim(p_node_type),btrim(p_external_id),p_label,p_criticality,p_attributes)
    on conflict (tenant_id,node_type,external_id) do update
    set last_seen=now(), label=coalesce(excluded.label,twin_nodes.label),
        criticality=greatest(twin_nodes.criticality,excluded.criticality),
        attributes=twin_nodes.attributes || excluded.attributes
    returning id into v_id;
    return v_id;
end;
$$;
revoke all on function twin_upsert_node(uuid,text,text,text,real,jsonb) from public, anon, authenticated;
grant execute on function twin_upsert_node(uuid,text,text,text,real,jsonb) to service_role;

create or replace function twin_upsert_edge(
    p_tenant uuid, p_source uuid, p_target uuid,
    p_relation text, p_weight real, p_criticality real
)
returns void
language plpgsql security definer set search_path = public
as $$
declare v_source_tenant uuid; v_target_tenant uuid;
begin
    select tenant_id into v_source_tenant from twin_nodes where id=p_source;
    select tenant_id into v_target_tenant from twin_nodes where id=p_target;
    if p_tenant is null or p_source is null or p_target is null or p_source=p_target
       or v_source_tenant is null or v_target_tenant is null
       or v_source_tenant <> p_tenant or v_target_tenant <> p_tenant then
        raise exception 'twin edge tenant mismatch';
    end if;
    if p_weight is null or p_weight < 0 or p_weight > 10 then raise exception 'edge weight out of range'; end if;
    if p_criticality is null or p_criticality < 0 or p_criticality > 1 then raise exception 'edge criticality out of range'; end if;
    insert into twin_edges(tenant_id,source_id,target_id,relation,weight,criticality)
    values(p_tenant,p_source,p_target,p_relation,p_weight,p_criticality)
    on conflict(source_id,target_id,relation) do update
    set tenant_id=excluded.tenant_id,last_seen=now(),
        weight=greatest(twin_edges.weight,excluded.weight),
        criticality=greatest(twin_edges.criticality,excluded.criticality);
end;
$$;
revoke all on function twin_upsert_edge(uuid,uuid,uuid,text,real,real) from public, anon, authenticated;
grant execute on function twin_upsert_edge(uuid,uuid,uuid,text,real,real) to service_role;

create or replace function twin_record_simulation(
    p_tenant uuid,p_action text,p_target_node uuid,p_args jsonb,p_requested_by uuid,
    p_status text,p_impact_score real,p_cascade_size integer,p_affected_nodes jsonb,
    p_critical_impact jsonb,p_recommendation text,p_duration_ms integer
)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_id uuid; v_target_tenant uuid;
begin
    select tenant_id into v_target_tenant from twin_nodes where id=p_target_node;
    if v_target_tenant is null or v_target_tenant <> p_tenant then raise exception 'target node tenant mismatch'; end if;
    if p_args is null or jsonb_typeof(p_args) <> 'object' then raise exception 'args must be object'; end if;
    if p_affected_nodes is null or jsonb_typeof(p_affected_nodes) <> 'array' or jsonb_array_length(p_affected_nodes)>500 then raise exception 'affected_nodes invalid'; end if;
    if p_critical_impact is null or jsonb_typeof(p_critical_impact) <> 'array' or jsonb_array_length(p_critical_impact)>100 then raise exception 'critical_impact invalid'; end if;
    if p_status not in ('pending','running','complete','failed') then raise exception 'invalid simulation status'; end if;
    if p_impact_score is not null and (p_impact_score<0 or p_impact_score>1) then raise exception 'impact out of range'; end if;
    if p_cascade_size is not null and (p_cascade_size<0 or p_cascade_size>1000000) then raise exception 'cascade size out of range'; end if;
    if p_duration_ms is not null and p_duration_ms<0 then raise exception 'duration out of range'; end if;
    insert into twin_simulations(
        tenant_id,action,target_node_id,args,requested_by,status,impact_score,cascade_size,
        affected_nodes,critical_impact,recommendation,duration_ms
    ) values (
        p_tenant,p_action,p_target_node,p_args,p_requested_by,p_status,p_impact_score,p_cascade_size,
        p_affected_nodes,p_critical_impact,p_recommendation,p_duration_ms
    ) returning id into v_id;
    return v_id;
end;
$$;
revoke all on function twin_record_simulation(uuid,text,uuid,jsonb,uuid,text,real,integer,jsonb,jsonb,text,integer)
from public, anon, authenticated;
grant execute on function twin_record_simulation(uuid,text,uuid,jsonb,uuid,text,real,integer,jsonb,jsonb,text,integer) to service_role;

create or replace function twin_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public
as $$
    select jsonb_build_object(
        'nodes',(select count(*) from twin_nodes where tenant_id=p_tenant),
        'edges',(select count(*) from twin_edges where tenant_id=p_tenant),
        'simulations',(select count(*) from twin_simulations where tenant_id=p_tenant),
        'avg_impact',(select coalesce(avg(impact_score),0) from twin_simulations where tenant_id=p_tenant and status='complete')
    );
$$;
revoke all on function twin_stats(uuid) from public, anon, authenticated;
grant execute on function twin_stats(uuid) to service_role;


-- ===== SOURCE sql/066_knowledge.sql =====
-- Knowledge Engine foundation: global knowledge graph, guides, contextual hints,
-- deterministic recommendations, support tickets, and bounded lexical search.
-- Pricing and branding are intentionally NOT part of this migration.

create table kg_nodes (
    id text primary key check (length(btrim(id)) between 1 and 160),
    kind text not null check (kind in (
        'service','feature','api','guide','concept','integration','pricing',
        'partner','defense','action'
    )),
    label text not null check (length(btrim(label)) between 1 and 300),
    summary text check (summary is null or length(summary) <= 4000),
    service_id text,
    tags text[] not null default '{}',
    embedding real[],
    metadata jsonb not null default '{}'::jsonb
        check (jsonb_typeof(metadata) = 'object'),
    priority integer not null default 100 check (priority >= 0 and priority <= 100000)
);

create index kg_nodes_kind_priority on kg_nodes(kind, priority, id);
create index kg_nodes_service on kg_nodes(service_id);
create index kg_nodes_tags on kg_nodes using gin(tags);
create index kg_nodes_fts on kg_nodes using gin (
    to_tsvector('simple',
        coalesce(label,'') || ' ' ||
        coalesce(summary,'') || ' ' ||
        coalesce(array_to_string(tags,' '),''))
);

create table kg_edges (
    src_id text not null references kg_nodes(id) on delete cascade,
    dst_id text not null references kg_nodes(id) on delete cascade,
    relation text not null check (relation in (
        'explains','includes','requires','integrates_with','priced_as',
        'governs','supersedes','belongs_to','guides','precedes','related_to'
    )),
    weight real not null default 1.0 check (weight >= 0 and weight <= 10),
    primary key (src_id, dst_id, relation),
    check (src_id <> dst_id)
);

create index kg_edges_src on kg_edges(src_id, relation, dst_id);
create index kg_edges_dst on kg_edges(dst_id, relation, src_id);

create table guides (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{0,119}$'),
    title text not null check (length(btrim(title)) between 1 and 300),
    summary text check (summary is null or length(summary) <= 4000),
    audience text not null check (audience in ('visitor','client','partner','developer','admin')),
    category text not null check (length(btrim(category)) between 1 and 120),
    estimated_minutes integer not null default 5 check (estimated_minutes between 1 and 1440),
    difficulty text not null default 'beginner'
        check (difficulty in ('beginner','intermediate','advanced')),
    prerequisite_ids uuid[] not null default '{}',
    tags text[] not null default '{}',
    enabled boolean not null default true,
    priority integer not null default 100 check (priority >= 0 and priority <= 100000),
    created_at timestamptz not null default now()
);

create index guides_audience_priority on guides(audience, priority, slug);
create index guides_tags on guides using gin(tags);

create table guide_steps (
    id uuid primary key default gen_random_uuid(),
    guide_id uuid not null references guides(id) on delete cascade,
    step_no integer not null check (step_no >= 1 and step_no <= 500),
    title text not null check (length(btrim(title)) between 1 and 300),
    body_md text not null check (length(body_md) <= 20000),
    action_url text check (action_url is null or length(action_url) <= 2000),
    action_label text check (action_label is null or length(action_label) <= 200),
    verify_kind text check (verify_kind in ('none','api_call','page_state','code_entered')),
    verify_payload jsonb not null default '{}'::jsonb
        check (jsonb_typeof(verify_payload) = 'object'),
    unique (guide_id, step_no)
);

create index guide_steps_guide on guide_steps(guide_id, step_no);

create table context_hints (
    id uuid primary key default gen_random_uuid(),
    page_route text not null check (length(btrim(page_route)) between 1 and 500),
    element_key text not null check (length(btrim(element_key)) between 1 and 200),
    title text not null check (length(btrim(title)) between 1 and 300),
    body_md text not null check (length(body_md) <= 12000),
    guide_slug text references guides(slug) on delete set null,
    doc_url text check (doc_url is null or length(doc_url) <= 2000),
    api_url text check (api_url is null or length(api_url) <= 2000),
    audience text[] not null default array['client'],
    priority integer not null default 100 check (priority >= 0 and priority <= 100000),
    unique (page_route, element_key)
);

create index context_hints_route_priority on context_hints(page_route, priority, element_key);
create index context_hints_audience on context_hints using gin(audience);

create table recommendation_rules (
    id uuid primary key default gen_random_uuid(),
    name text not null check (length(btrim(name)) between 1 and 300),
    condition jsonb not null check (jsonb_typeof(condition) = 'object'),
    kind text not null check (kind in (
        'enable_service','read_guide','add_partner','upgrade_plan',
        'configure_api','invite_team','harden_setting'
    )),
    target jsonb not null check (jsonb_typeof(target) = 'object'),
    title text not null check (length(btrim(title)) between 1 and 300),
    body_md text not null check (length(body_md) <= 12000),
    cta_label text check (cta_label is null or length(cta_label) <= 200),
    cta_url text check (cta_url is null or length(cta_url) <= 2000),
    base_score real not null default 0.5 check (base_score >= 0 and base_score <= 1),
    priority integer not null default 100 check (priority >= 0 and priority <= 100000),
    enabled boolean not null default true,
    created_at timestamptz not null default now()
);

create index recommendation_rules_active on recommendation_rules(enabled, priority, id);

create table recommendation_impressions (
    id bigint generated always as identity primary key,
    tenant_id uuid not null references tenants(id) on delete cascade,
    user_id uuid references auth.users(id) on delete set null,
    rule_id uuid not null references recommendation_rules(id) on delete cascade,
    shown_at timestamptz not null default now(),
    clicked boolean not null default false,
    clicked_at timestamptz,
    check ((clicked = false and clicked_at is null) or (clicked = true and clicked_at is not null))
);

create index recommendation_impressions_tenant on recommendation_impressions(tenant_id, shown_at desc);
create index recommendation_impressions_rule on recommendation_impressions(tenant_id, rule_id, shown_at desc);

create table tickets (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    opened_by uuid references auth.users(id) on delete set null,
    subject text not null check (length(btrim(subject)) between 1 and 500),
    body text not null check (length(body) between 1 and 50000),
    severity text not null default 'normal'
        check (severity in ('low','normal','high','critical')),
    status text not null default 'open'
        check (status in ('open','pending','escalated','resolved','closed')),
    assigned_to uuid references admin_users(user_id) on delete set null,
    related_service text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index tickets_tenant_created on tickets(tenant_id, created_at desc);
create index tickets_assign_status on tickets(assigned_to, status, created_at desc);

create table ticket_messages (
    id bigint generated always as identity primary key,
    ticket_id uuid not null references tickets(id) on delete cascade,
    author_id uuid not null,
    author_kind text not null check (author_kind in ('client','admin')),
    body text not null check (length(body) between 1 and 50000),
    attachments jsonb not null default '[]'::jsonb
        check (jsonb_typeof(attachments) = 'array'),
    created_at timestamptz not null default now()
);

create index ticket_messages_ticket_created on ticket_messages(ticket_id, created_at, id);

do $$
begin
    if to_regclass('public.admin_users') is not null then
        alter table public.admin_users
            add column if not exists sector text,
            add column if not exists on_call boolean not null default false,
            add column if not exists timezone text not null default 'UTC';
        alter table public.admin_users
            drop constraint if exists admin_users_sector_check;
        alter table public.admin_users
            add constraint admin_users_sector_check check (
                sector is null or sector in (
                    'ops','support','billing','security','compliance','engineering','root'
                )
            );
    end if;
end $$;

alter table kg_nodes enable row level security;
alter table kg_edges enable row level security;
alter table guides enable row level security;
alter table guide_steps enable row level security;
alter table context_hints enable row level security;
alter table recommendation_rules enable row level security;
alter table recommendation_impressions enable row level security;
alter table tickets enable row level security;
alter table ticket_messages enable row level security;

-- The API is the authorization boundary. No direct Data API access is granted.
revoke all on table kg_nodes, kg_edges, guides, guide_steps, context_hints,
    recommendation_rules, recommendation_impressions, tickets, ticket_messages
    from public, anon, authenticated;
grant select, insert, update, delete on kg_nodes, kg_edges, guides, guide_steps,
    context_hints, recommendation_rules, recommendation_impressions, tickets,
    ticket_messages to service_role;

create or replace function kg_search(p_query text, p_limit integer default 30)
returns table (
    node_id text, kind text, label text, summary text,
    service_id text, deep_link text, score real
)
language sql
stable
set search_path = public
as $$
    with q as (
        select websearch_to_tsquery('simple', left(trim(p_query), 1000)) as tsq
    )
    select
        n.id,
        n.kind,
        n.label,
        n.summary,
        n.service_id,
        case n.kind
            when 'service' then '/services/' || coalesce(n.service_id, n.id)
            when 'api' then '/services/' || coalesce(n.service_id, n.id) || '#api_reference'
            when 'guide' then '/guides/' || coalesce(n.metadata->>'slug', n.id)
            when 'pricing' then '/pricing#' || n.id
            when 'partner' then '/partners'
            else '/services/' || coalesce(n.service_id, '')
        end,
        ts_rank_cd(
            to_tsvector('simple',
                coalesce(n.label,'') || ' ' ||
                coalesce(n.summary,'') || ' ' ||
                coalesce(array_to_string(n.tags,' '),'')
            ),
            q.tsq
        )::real
    from kg_nodes n
    cross join q
    where trim(p_query) <> ''
      and to_tsvector('simple',
            coalesce(n.label,'') || ' ' ||
            coalesce(n.summary,'') || ' ' ||
            coalesce(array_to_string(n.tags,' '),'')
          ) @@ q.tsq
    order by score desc, n.priority asc, n.id asc
    limit least(greatest(coalesce(p_limit, 30), 1), 100);
$$;

revoke all on function kg_search(text, integer) from public, anon, authenticated;
grant execute on function kg_search(text, integer) to service_role;

create or replace function knowledge_record_impression(
    p_tenant uuid, p_user uuid, p_rule uuid
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id bigint;
begin
    if p_tenant is null or not exists (select 1 from tenants where id = p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_rule is null or not exists (
        select 1 from recommendation_rules where id = p_rule and enabled = true
    ) then
        raise exception 'unknown recommendation rule';
    end if;
    insert into recommendation_impressions(tenant_id, user_id, rule_id)
    values (p_tenant, p_user, p_rule)
    returning id into v_id;
    return v_id;
end;
$$;

revoke all on function knowledge_record_impression(uuid, uuid, uuid)
    from public, anon, authenticated;
grant execute on function knowledge_record_impression(uuid, uuid, uuid) to service_role;

commit;
