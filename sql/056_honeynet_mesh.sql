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
