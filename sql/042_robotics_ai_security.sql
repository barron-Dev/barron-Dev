create table if not exists robot_fleets (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 name text not null, kind text not null check(kind in('drone','amr','quadruped','manipulator','autonomous_vehicle','sensor_array')),
 framework text check(framework in('ros2','ros1','custom','px4','ardupilot')),
 middleware text check(middleware in('dds','zenoh','mqtt','custom')), country text, fleet_size int not null default 0,
 created_at timestamptz not null default now()
);
create index if not exists idx_robot_fleets_tenant on robot_fleets(tenant_id);
alter table robot_fleets enable row level security;
drop policy if exists robot_fleets_tenant on robot_fleets;
create policy robot_fleets_tenant on robot_fleets using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists robot_devices (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 fleet_id uuid not null references robot_fleets(id) on delete cascade, device_id uuid references devices(id) on delete set null,
 serial text not null, firmware text, sros2_enabled boolean not null default false, last_heartbeat timestamptz,
 created_at timestamptz not null default now(), unique(fleet_id,serial)
);
create index if not exists idx_robot_devices_fleet on robot_devices(fleet_id);
alter table robot_devices enable row level security;
drop policy if exists robot_devices_tenant on robot_devices;
create policy robot_devices_tenant on robot_devices using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists robot_topics (
 id bigserial primary key, tenant_id uuid not null references tenants(id) on delete cascade,
 robot_id uuid not null references robot_devices(id) on delete cascade, topic_name text not null, msg_type text not null,
 publisher_count int not null default 0, subscriber_count int not null default 0,
 first_seen timestamptz not null default now(), last_seen timestamptz not null default now()
);
create index if not exists idx_robot_topics_robot on robot_topics(robot_id,topic_name);
alter table robot_topics enable row level security;
create policy robot_topics_tenant on robot_topics using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists robot_sboms (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 robot_id uuid not null references robot_devices(id) on delete cascade, sbom_version text not null, component_count int not null default 0,
 cve_count int not null default 0, critical_cves int not null default 0, sbom_document jsonb not null default '{}'::jsonb,
 generated_at timestamptz not null default now()
);
alter table robot_sboms enable row level security;
create policy robot_sboms_tenant on robot_sboms using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists robot_anomalies (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 robot_id uuid not null references robot_devices(id) on delete cascade,
 kind text not null check(kind in('unauth_publisher','topic_hijack','msg_spoof','keystore_access','unexpected_topic','frequency_anomaly','firmware_downgrade','rogue_node','command_injection')),
 severity text not null default 'high' check(severity in('medium','high','critical')),
 evidence jsonb not null default '{}'::jsonb, status text not null default 'new' check(status in('new','investigating','resolved','false_positive')),
 case_id uuid references crime_cases(id) on delete set null, first_seen timestamptz not null default now(), last_seen timestamptz not null default now()
);
create index if not exists idx_robot_anomalies_tenant on robot_anomalies(tenant_id,first_seen desc);
alter table robot_anomalies enable row level security;
create policy robot_anomalies_tenant on robot_anomalies using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists ai_agent_manifests (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade, agent_id text not null,
 framework text not null, model text not null, tools jsonb not null default '[]'::jsonb, mcp_servers jsonb not null default '[]'::jsonb,
 signed boolean not null default false, signing_key_id text, manifest_hash text not null, created_at timestamptz not null default now(),
 unique(tenant_id,agent_id,manifest_hash)
);
create index if not exists idx_ai_manifests_tenant on ai_agent_manifests(tenant_id,agent_id);
alter table ai_agent_manifests enable row level security;
create policy ai_manifests_tenant on ai_agent_manifests using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists ai_tool_risks (
 id bigserial primary key, tenant_id uuid not null references tenants(id) on delete cascade, tool_name text not null, source text not null,
 risk_class text not null, risk_score real not null default 0, capabilities text[] not null default '{}', signature_hash text,
 approved boolean not null default false, first_seen timestamptz not null default now(), last_seen timestamptz not null default now()
);
create index if not exists idx_ai_tool_risks_tenant on ai_tool_risks(tenant_id,risk_score desc);
alter table ai_tool_risks enable row level security;
create policy ai_tool_risks_tenant on ai_tool_risks using(tenant_id=(auth.jwt()->>'tenant_id')::uuid);