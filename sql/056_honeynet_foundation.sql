-- Cyclothone Honeynet Mesh foundation.
-- Deliberately uses 056 because 054 is already occupied by global-platform and streaming work is 055.

create table if not exists honey_templates (
  id text primary key,
  name text not null,
  category text not null check (category in ('server','database','api_key','user','email','repo','wallet','share','document','credential','token','payment','console','backup','camera','sensor')),
  platform text[] not null default '{}',
  description text,
  severity text not null default 'critical' check (severity in ('high','critical')),
  content_template text not null,
  default_paths jsonb not null default '{}'::jsonb,
  beacon_enabled boolean not null default false,
  enabled boolean not null default true
);

insert into honey_templates(id,name,category,platform,description,content_template,default_paths,beacon_enabled) values
('aws_admin_keys','AWS admin access keys','api_key',array['linux','windows','macos'],'Synthetic AWS credentials for deception only',
E'[default]\naws_access_key_id = {{aws_key}}\naws_secret_access_key = {{aws_secret}}\nregion = {{region}}\noutput = json',
'{"linux":["/root/.aws/credentials","/home/{user}/.aws/credentials"],"windows":["C:\\Users\\{user}\\.aws\\credentials"],"macos":["/Users/{user}/.aws/credentials"]}',false),
('ssh_root_key','SSH root private key','credential',array['linux','macos'],'Synthetic private key marker',
E'-----BEGIN OPENSSH PRIVATE KEY-----\n{{b64_blob}}\n-----END OPENSSH PRIVATE KEY-----\n',
'{"linux":["/root/.ssh/id_ed25519","/backup/.ssh/id_ed25519"],"macos":["/var/root/.ssh/id_ed25519"]}',false),
('prod_db_creds','Production database credentials','database',array['linux','windows'],'Synthetic PostgreSQL credential file',
E'host={{db_host}}\nport=5432\nuser=postgres\npassword={{db_pass}}\ndbname=production',
'{"linux":["/root/.pgpass","/opt/app/.pgpass"],"windows":["C:\\Users\\{user}\\.pgpass"]}',false),
('ceo_email_mbox','CEO email archive','email',array['linux','windows','macos'],'Synthetic mailbox containing beaconable content',
E'{{mbox_blob}}',
'{"linux":["/home/{user}/Documents/ceo-mail.mbox"],"windows":["C:\\Users\\{user}\\Documents\\ceo.mbox"],"macos":["/Users/{user}/Documents/ceo.mbox"]}',true),
('swift_creds','SWIFT operator credentials','credential',array['windows'],'Synthetic SWIFT configuration',
E'[SWIFT]\noperator={{username}}\nbic={{bic}}\nendpoint={{endpoint}}\ntoken={{token}}',
'{"windows":["C:\\ProgramData\\SWIFT\\operator.ini"]}',true),
('crypto_wallet_seed','Crypto wallet seed phrase','wallet',array['linux','windows','macos'],'Synthetic non-funding wallet marker',
E'{{mnemonic}}\nAddress: {{wallet_address}}\nDerivation: m/44''/60''/0''/0/0',
'{"linux":["/home/{user}/.wallet/seed.txt","/root/wallet-seed.txt"],"windows":["C:\\Users\\{user}\\Documents\\seed.txt"],"macos":["/Users/{user}/Documents/seed.txt"]}',false),
('hr_payroll_xlsx','Payroll spreadsheet','document',array['linux','windows'],'Synthetic payroll marker',
E'{{xlsx_blob}}',
'{"linux":["/srv/hr/payroll-{{year}}.xlsx"],"windows":["C:\\Users\\{user}\\Documents\\payroll-{{year}}.xlsx"]}',false),
('admin_share','Admin file share','share',array['windows'],'Synthetic administrative database marker',
E'{{sqlite_blob}}',
'{"windows":["C:\\Users\\{user}\\Desktop\\admin-backup\\creds.db"]}',false),
('k8s_service_token','Kubernetes service account token','token',array['linux'],'Synthetic service token marker',
E'{{jwt}}',
'{"linux":["/var/run/secrets/kubernetes.io/serviceaccount/token"]}',true),
('vpn_config','VPN client config','credential',array['linux','windows','macos'],'Synthetic WireGuard configuration',
E'[Interface]\nPrivateKey = {{wg_key}}\nAddress = 10.8.0.42/24\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = {{wg_pub}}\nEndpoint = vpn.{{domain}}:51820',
'{"linux":["/etc/wireguard/wg0.conf"],"windows":["C:\\Users\\{user}\\Documents\\vpn.conf"],"macos":["/Users\\{user}\\Documents\\vpn.conf"]}',true)
on conflict(id) do update set name=excluded.name,category=excluded.category,platform=excluded.platform,
description=excluded.description,content_template=excluded.content_template,default_paths=excluded.default_paths,
beacon_enabled=excluded.beacon_enabled,enabled=excluded.enabled;

create table if not exists honey_assets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  template_id text not null references honey_templates(id),
  device_id uuid references devices(id) on delete set null,
  path text,
  url text,
  hostname text,
  token_id text not null unique,
  token_secret_ciphertext text,
  token_secret_hash text not null,
  beacon_url text,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  content_ref text not null,
  status text not null default 'deployed' check (status in ('deployed','tripped','removed','expired')),
  tripped_at timestamptz,
  tripped_count int not null default 0 check (tripped_count >= 0),
  deployed_at timestamptz not null default now(),
  expires_at timestamptz,
  unique(tenant_id,device_id,template_id,path)
);
create index if not exists idx_honey_assets_tenant on honey_assets(tenant_id,status);
create index if not exists idx_honey_assets_device on honey_assets(tenant_id,device_id,status);

create table if not exists honey_touches (
  id bigserial primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  asset_id uuid not null references honey_assets(id) on delete cascade,
  template_id text not null references honey_templates(id),
  touch_kind text not null check (touch_kind in ('file_read','file_write','file_delete','file_rename','file_execute','credential_use','beacon_http','beacon_dns','share_access','api_call','db_query')),
  actor_pid int,
  actor_process text,
  actor_user text,
  actor_cmdline text,
  actor_hash text,
  source_ip inet,
  source_country text,
  source_asn text,
  user_agent text,
  details jsonb not null default '{}'::jsonb,
  response_status text not null default 'pending' check (response_status in ('pending','isolated','case_opened','acknowledged','dismissed')),
  case_id uuid references crime_cases(id) on delete set null,
  observed_at timestamptz not null default now()
);
create index if not exists idx_honey_touches_tenant on honey_touches(tenant_id,observed_at desc);
create index if not exists idx_honey_touches_asset on honey_touches(asset_id,observed_at desc);

alter table honey_templates enable row level security;
alter table honey_assets enable row level security;
alter table honey_touches enable row level security;

revoke all on honey_assets,honey_touches from anon,authenticated;
drop policy if exists honey_templates_read on honey_templates;
create policy honey_templates_read on honey_templates for select to authenticated using (enabled=true);
drop policy if exists honey_assets_tenant on honey_assets;
create policy honey_assets_tenant on honey_assets for select to authenticated using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));
drop policy if exists honey_touches_tenant on honey_touches;
create policy honey_touches_tenant on honey_touches for select to authenticated using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create or replace function honey_mark_tripped(p_tenant uuid,p_asset uuid)
returns void language plpgsql security definer set search_path=public as $$
begin
  if not exists(select 1 from honey_assets where id=p_asset and tenant_id=p_tenant) then
    raise exception 'honey asset not found';
  end if;
  update honey_assets
     set status='tripped',tripped_at=coalesce(tripped_at,now()),tripped_count=tripped_count+1
   where id=p_asset and tenant_id=p_tenant;
end $$;
revoke all on function honey_mark_tripped(uuid,uuid) from public,anon,authenticated;
grant execute on function honey_mark_tripped(uuid,uuid) to service_role;

create or replace function honey_coverage(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public as $$
  select jsonb_build_object(
    'total_assets',(select count(*) from honey_assets where tenant_id=p_tenant),
    'deployed',(select count(*) from honey_assets where tenant_id=p_tenant and status='deployed'),
    'tripped',(select count(*) from honey_assets where tenant_id=p_tenant and status='tripped'),
    'touches_30d',(select count(*) from honey_touches where tenant_id=p_tenant and observed_at>now()-interval '30 days'),
    'devices_protected',(select count(distinct device_id) from honey_assets where tenant_id=p_tenant and device_id is not null)
  )
$$;
revoke all on function honey_coverage(uuid) from public,anon,authenticated;
grant execute on function honey_coverage(uuid) to service_role;

create or replace function honey_record_touch(
  p_tenant uuid,p_asset uuid,p_touch_kind text,p_actor jsonb default '{}'::jsonb,
  p_source_ip inet default null,p_source_country text default null,p_source_asn text default null,
  p_user_agent text default null,p_details jsonb default '{}'::jsonb
) returns bigint language plpgsql security definer set search_path=public as $$
declare v_id bigint;
begin
  if not exists(select 1 from honey_assets where id=p_asset and tenant_id=p_tenant and status <> 'removed') then
    raise exception 'honey asset not found';
  end if;
  insert into honey_touches(tenant_id,asset_id,template_id,touch_kind,actor_pid,actor_process,actor_user,actor_cmdline,actor_hash,source_ip,source_country,source_asn,user_agent,details)
  select p_tenant,id,template_id,p_touch_kind,
    nullif(p_actor->>'pid','')::int,p_actor->>'process',p_actor->>'user',p_actor->>'cmdline',p_actor->>'hash',
    p_source_ip,p_source_country,p_source_asn,p_user_agent,coalesce(p_details,'{}'::jsonb)
  from honey_assets where id=p_asset and tenant_id=p_tenant;
  select currval(pg_get_serial_sequence('honey_touches','id')) into v_id;
  perform honey_mark_tripped(p_tenant,p_asset);
  return v_id;
end $$;
revoke all on function honey_record_touch(uuid,uuid,text,jsonb,inet,text,text,text,jsonb) from public,anon,authenticated;
grant execute on function honey_record_touch(uuid,uuid,text,jsonb,inet,text,text,text,jsonb) to service_role;
