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
