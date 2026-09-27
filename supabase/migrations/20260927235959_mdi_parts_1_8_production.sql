begin;

create extension if not exists pgcrypto;
create extension if not exists pg_trgm;
create extension if not exists unaccent;
create extension if not exists vector;

create table if not exists public.mdi_subject_tenants(
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  subject_id uuid not null references public.mdi_subjects(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(tenant_id,subject_id)
);
create index if not exists mdi_subject_tenants_subject_idx on public.mdi_subject_tenants(subject_id);
alter table public.mdi_subject_tenants enable row level security;
drop policy if exists mdi_subject_tenants_service on public.mdi_subject_tenants;
create policy mdi_subject_tenants_service on public.mdi_subject_tenants for all to service_role using(true) with check(true);

create table if not exists public.mdi_rf_observations(
 id uuid primary key default gen_random_uuid(),
 observer_id uuid, subject_id uuid references public.mdi_subjects(id) on delete set null,
 radio text not null check(radio in('cellular','wifi','ble','gnss','lora','nfc')),
 observed_at timestamptz not null default now(),
 lat double precision, lon double precision, h3_r9 text,
 mcc char(3), mnc char(3), lac text, cid text, arfcn bigint, pci int, rx_level_dbm numeric, timing_advance numeric,
 bssid_hash text, ssid text, channel int, rssi numeric, security text, wps boolean,
 ble_mac_hash text, ble_name text, ble_service_uuids text[], tx_power numeric,
 gnss_sats int, gnss_cn0 numeric, spoof_flag boolean,
 raw jsonb not null default '{}', case_id uuid, created_at timestamptz not null default now()
);
create index if not exists mdi_rf_obs_subject_time on public.mdi_rf_observations(subject_id,observed_at desc);
create index if not exists mdi_rf_obs_radio_time on public.mdi_rf_observations(radio,observed_at desc);
create index if not exists mdi_rf_obs_cell on public.mdi_rf_observations(mcc,mnc,lac,cid,observed_at desc);
create index if not exists mdi_rf_obs_bssid on public.mdi_rf_observations(bssid_hash,observed_at desc);
create table if not exists public.mdi_rf_trusted(
 id uuid primary key default gen_random_uuid(),fingerprint_hash text not null unique,radio text not null,owner_org uuid,
 label text,valid_from timestamptz not null default now(),valid_to timestamptz,confidence numeric(4,3) not null default .9,source text not null
);
create table if not exists public.mdi_rf_threats(
 id uuid primary key default gen_random_uuid(),observation_id uuid references public.mdi_rf_observations(id) on delete cascade,
 threat_type text not null,severity smallint not null check(severity between 1 and 5),confidence numeric(4,3) not null,
 algorithm text not null,explanation jsonb not null default '{}',case_id uuid,created_at timestamptz not null default now()
);
create index if not exists mdi_rf_threats_time on public.mdi_rf_threats(created_at desc);
create table if not exists public.mdi_wifi_probe_clusters(
 id uuid primary key default gen_random_uuid(),mac_hash text not null,h3_r9 text not null,window_start timestamptz not null,ssids text[] not null default '{}',observation_count int not null default 0,unique(mac_hash,h3_r9,window_start)
);

create table if not exists public.mdi_ss7_events(
 id uuid primary key default gen_random_uuid(),occurred_at timestamptz not null,opcode text not null,gt_orig text,gt_dest text,imsi_hash text,msisdn_hash text,country_from char(2),country_to char(2),latency_ms int,anomaly_tags text[] not null default '{}',raw jsonb not null default '{}',created_at timestamptz not null default now()
);
create index if not exists mdi_ss7_time on public.mdi_ss7_events(occurred_at desc);
create table if not exists public.mdi_ss7_risk(
 id uuid primary key default gen_random_uuid(),subject_id uuid references public.mdi_subjects(id) on delete cascade,score numeric(5,2) not null,reason jsonb not null default '{}',computed_at timestamptz not null default now()
);

create table if not exists public.mdi_a2p_brands(
 id uuid primary key default gen_random_uuid(),sender_id text not null,country_iso2 char(2) not null,display_name text not null,category text,owner_org uuid,public_key text,status text not null default 'pending' check(status in('pending','verified','suspended')),created_at timestamptz not null default now(),unique(sender_id,country_iso2)
);
create table if not exists public.mdi_a2p_aliases(
 id uuid primary key default gen_random_uuid(),brand_id uuid not null references public.mdi_a2p_brands(id) on delete cascade,alias text not null,unique(brand_id,alias)
);
create table if not exists public.mdi_a2p_routes(
 id uuid primary key default gen_random_uuid(),brand_id uuid references public.mdi_a2p_brands(id) on delete set null,route_fingerprint text not null,carrier text,country_iso2 char(2),status text not null default 'unknown',observed_at timestamptz not null default now()
);
create table if not exists public.mdi_a2p_nonces(
 nonce_hash text primary key,expires_at timestamptz not null,created_at timestamptz not null default now()
);

create table if not exists public.mdi_otp_sessions(
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants(id) on delete cascade,subject_id uuid references public.mdi_subjects(id) on delete set null,
 msisdn_hash text not null,imei_hash text,imsi_hash text,iccid_hash text,cell_id text,h3_r9 text,ip_asn text,device_fp_hash text,
 purpose text not null,issued_at timestamptz not null,expires_at timestamptz not null,otp_hash text not null,attempts int not null default 0,status text not null default 'issued' check(status in('issued','verified','expired','blocked')),created_at timestamptz not null default now()
);
create index if not exists mdi_otp_tenant_time on public.mdi_otp_sessions(tenant_id,created_at desc);

create table if not exists public.mdi_wallet_accounts(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,network text not null,address_hash text not null,owner_subject_id uuid references public.mdi_subjects(id) on delete set null,kyc_status text,status text not null default 'active',created_at timestamptz not null default now(),unique(network,address_hash)
);
create table if not exists public.mdi_wallet_tx(
 id uuid primary key default gen_random_uuid(),network text not null,tx_hash text not null,from_wallet uuid references public.mdi_wallet_accounts(id) on delete set null,to_wallet uuid references public.mdi_wallet_accounts(id) on delete set null,amount numeric,asset text,occurred_at timestamptz not null,raw jsonb not null default '{}',unique(network,tx_hash)
);
create index if not exists mdi_wallet_tx_time on public.mdi_wallet_tx(occurred_at desc);
create table if not exists public.mdi_shared_signals(
 id uuid primary key default gen_random_uuid(),source_org uuid,subject_hash text not null,risk_label text not null,confidence numeric(4,3),signal_type text not null,evidence_ref text,expires_at timestamptz,created_at timestamptz not null default now()
);

create table if not exists public.mdi_payments(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,subject_id uuid references public.mdi_subjects(id) on delete set null,
 uetr text unique,amount numeric(30,8),currency char(3),bic_orig text,bic_dest text,iban_orig_hash text,iban_dest_hash text,country_from char(2),country_to char(2),purpose_code text,channel text,status text not null default 'received',
 raw jsonb not null default '{}',occurred_at timestamptz not null,created_at timestamptz not null default now()
);
create index if not exists mdi_payments_tenant_time on public.mdi_payments(tenant_id,occurred_at desc);
create table if not exists public.mdi_high_risk_corridors(
country_from char(2) not null,country_to char(2) not null,risk_score numeric(5,2) not null,reason text,source_url text,updated_at timestamptz not null default now(),primary key(country_from,country_to)
);
create table if not exists public.mdi_payment_scores(
id uuid primary key default gen_random_uuid(),payment_id uuid not null references public.mdi_payments(id) on delete cascade,score numeric(5,2) not null,band text not null,reasons jsonb not null default '{}',computed_at timestamptz not null default now()
);

create table if not exists public.mdi_crypto_wallets(
 id uuid primary key default gen_random_uuid(),network text not null,address_hash text not null,sanctions_flag boolean not null default false,mixer_flag boolean not null default false,metadata jsonb not null default '{}',unique(network,address_hash)
);
create table if not exists public.mdi_crypto_tx(
 id uuid primary key default gen_random_uuid(),network text not null,tx_hash text not null,from_wallet uuid references public.mdi_crypto_wallets(id) on delete set null,to_wallet uuid references public.mdi_crypto_wallets(id) on delete set null,amount numeric,asset text,occurred_at timestamptz not null,raw jsonb not null default '{}',unique(network,tx_hash)
);
create table if not exists public.mdi_crypto_exposure(
 id uuid primary key default gen_random_uuid(),wallet_id uuid not null references public.mdi_crypto_wallets(id) on delete cascade,hops int not null,score numeric(5,2) not null,reasons jsonb not null default '{}',computed_at timestamptz not null default now()
);

create table if not exists public.mdi_sanctions_entities(
 id uuid primary key default gen_random_uuid(),source text not null,external_id text,entity_type text not null,name text not null,name_norm text not null,aliases text[] not null default '{}',country char(2),dob date,program text,pep boolean not null default false,raw jsonb not null default '{}',updated_at timestamptz not null default now(),unique(source,coalesce(external_id,name_norm))
);
create index if not exists mdi_sanctions_name_trgm on public.mdi_sanctions_entities using gin(name_norm extensions.gin_trgm_ops);
create table if not exists public.mdi_sanctions_hits(
 id uuid primary key default gen_random_uuid(),subject_id uuid references public.mdi_subjects(id) on delete set null,entity_id uuid not null references public.mdi_sanctions_entities(id) on delete cascade,similarity numeric(5,4) not null,reason jsonb not null default '{}',created_at timestamptz not null default now()
);

create table if not exists public.mdi_sar_reports(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,case_id uuid,subject_id uuid references public.mdi_subjects(id) on delete set null,status text not null default 'draft' check(status in('draft','review','submitted','rejected')),narrative text,indicators text[] not null default '{}',amount_total numeric,reporting_jurisdiction text,created_at timestamptz not null default now(),updated_at timestamptz not null default now()
);
create table if not exists public.mdi_legal_requests(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,request_type text not null,jurisdiction text not null,authority_reference text,status text not null default 'pending',created_at timestamptz not null default now()
);
create table if not exists public.mdi_legal_playbooks(
 id uuid primary key default gen_random_uuid(),jurisdiction text not null,request_type text not null,route text not null,requirements jsonb not null default '{}',unique(jurisdiction,request_type)
);
create table if not exists public.mdi_notices(
 id uuid primary key default gen_random_uuid(),partner text not null,notice_type text not null,external_ref text,payload jsonb not null default '{}',status text not null default 'draft',created_at timestamptz not null default now()
);

create table if not exists public.mdi_freeze_orders(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,target_hash text not null,target_kind text not null,reason text not null,approved_by uuid,valid_from timestamptz not null,valid_to timestamptz not null,status text not null default 'pending'
);

create table if not exists public.mdi_evidence_packs(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,case_id uuid not null,payload jsonb not null,sha256 text not null,created_by uuid,chain_of_custody jsonb not null default '[]',created_at timestamptz not null default now()
);
create or replace function public.mdi_build_evidence_pack(p_case uuid,p_actor uuid)
returns uuid language plpgsql security invoker set search_path=public as $$
declare v_payload jsonb; v_id uuid;
begin
 select jsonb_build_object(
   'case_id',p_case,
   'observations',coalesce((select jsonb_agg(to_jsonb(x)) from (select id,subject_id,observed_at,signal_type,confidence,evidence_ref from mdi_location_signals where case_id=p_case order by observed_at) x),'[]'::jsonb),
   'rf_threats',coalesce((select jsonb_agg(to_jsonb(x)) from (select id,observation_id,threat_type,severity,confidence,algorithm,explanation from mdi_rf_threats where case_id=p_case order by created_at) x),'[]'::jsonb)
 ) into v_payload;
 insert into mdi_evidence_packs(case_id,payload,sha256,created_by,chain_of_custody)
 values(p_case,v_payload,encode(digest(v_payload::text,'sha256'),'hex'),p_actor,jsonb_build_array(jsonb_build_object('actor',p_actor,'at',now()))) returning id into v_id;
 return v_id;
end $$;

create or replace function public.mdi_risk_boost(p_subject uuid) returns numeric
language sql stable set search_path=public as $$
select least(100,coalesce(sum(case when severity>=4 then severity*4 else severity end),0)::numeric)
from public.mdi_rf_threats t join public.mdi_rf_observations o on o.id=t.observation_id
where o.subject_id=p_subject and t.created_at>now()-interval '7 days'
$$;

create table if not exists public.mdi_response_actions(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,subject_id uuid references public.mdi_subjects(id) on delete set null,case_id uuid,action text not null,reason text not null,auto_requested boolean not null default false,status text not null default 'proposed' check(status in('proposed','authorized','dispatched','completed','rejected','cancelled')),authorization_ref text,created_at timestamptz not null default now(),updated_at timestamptz not null default now()
);

create table if not exists public.mdi_compliance_rules(
 id uuid primary key default gen_random_uuid(),jurisdiction text not null,statute text not null,requirement text not null,applies_to text[] not null default '{}',data_category text[] not null default '{}',retention_days int,lawful_bases text[] not null default '{}',cross_border boolean not null default false,evidence text,source_url text,updated_at timestamptz not null default now(),unique(jurisdiction,statute,requirement)
);
create table if not exists public.mdi_compliance_findings(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,jurisdiction text not null,rule_id uuid references public.mdi_compliance_rules(id) on delete set null,case_id uuid,subject_id uuid references public.mdi_subjects(id) on delete set null,severity text not null,finding text not null,evidence jsonb not null default '{}',detected_at timestamptz not null default now(),remediated_at timestamptz
);
create table if not exists public.mdi_lawful_basis_log(
 id uuid primary key default gen_random_uuid(),tenant_id uuid references public.tenants(id) on delete cascade,subject_id uuid references public.mdi_subjects(id) on delete set null,purpose text not null,basis text not null,authority_reference text,expires_at timestamptz,created_by uuid,created_at timestamptz not null default now()
);
create table if not exists public.mdi_dsar_requests(
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants(id) on delete cascade,jurisdiction text not null,request_type text not null,subject_hash text not null,sla_deadline timestamptz not null,status text not null default 'received',created_by uuid,created_at timestamptz not null default now()
);

insert into public.mdi_compliance_rules(jurisdiction,statute,requirement,applies_to,data_category,retention_days,lawful_bases,cross_border,evidence,source_url)
values
('GDPR','GDPR','lawful basis and purpose limitation',ARRAY['mdi'],ARRAY['personal_data'],365,ARRAY['consent','contract','legal_obligation','legitimate_interests'],true,'documented processing purpose','https://eur-lex.europa.eu/eli/reg/2016/679/oj'),
('UAE_PDPL','UAE PDPL','lawful processing and cross-border controls',ARRAY['mdi'],ARRAY['personal_data'],365,ARRAY['consent','contract','legal_obligation'],true,'processing register','https://uaelegislation.gov.ae/'),
('SAUDI_PDPL','Saudi PDPL','purpose, retention and transfer controls',ARRAY['mdi'],ARRAY['personal_data'],365,ARRAY['consent','contract','legal_obligation'],true,'processing register','https://sdaia.gov.sa/'),
('POPIA','POPIA','processing limitation and retention controls',ARRAY['mdi'],ARRAY['personal_data'],365,ARRAY['consent','contract','legal_obligation'],true,'processing register','https://www.gov.za/'),
('DPDP_IN','Digital Personal Data Protection Act','notice, purpose and retention controls',ARRAY['mdi'],ARRAY['personal_data'],365,ARRAY['consent','legal_obligation'],true,'processing register','https://www.meity.gov.in/')
on conflict(jurisdiction,statute,requirement) do update set updated_at=now();

create table if not exists public.mdi_embeddings(
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants(id) on delete cascade,entity_kind text not null,entity_id uuid not null,content text not null,content_hash text not null,vector vector(768),model text not null,created_at timestamptz not null default now(),updated_at timestamptz not null default now(),unique(tenant_id,entity_kind,entity_id,model)
);
create index if not exists mdi_embeddings_tenant_idx on public.mdi_embeddings(tenant_id,entity_kind,entity_id);

create table if not exists public.mdi_copilot_threads(
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants(id) on delete cascade,user_id uuid,case_id uuid,title text,created_at timestamptz not null default now(),updated_at timestamptz not null default now()
);
create table if not exists public.mdi_copilot_messages(
 id uuid primary key default gen_random_uuid(),thread_id uuid not null references public.mdi_copilot_threads(id) on delete cascade,role text not null check(role in('user','assistant','tool')),content text not null,citations jsonb not null default '[]',created_at timestamptz not null default now()
);

create or replace function public.mdi_norm_name(p text) returns text language sql immutable set search_path=public as $$
select regexp_replace(lower(unaccent(coalesce(p,''))),'[^a-z0-9]+','','g')
$$;

create or replace function public.mdi_screen_name(p_name text,p_threshold numeric default .82)
returns table(entity_id uuid,name text,similarity numeric)
language sql stable set search_path=public as $$
select id,name,similarity(name_norm,public.mdi_norm_name(p_name))::numeric
from public.mdi_sanctions_entities
where similarity(name_norm,public.mdi_norm_name(p_name)) >= p_threshold
order by similarity(name_norm,public.mdi_norm_name(p_name)) desc limit 25
$$;

create or replace function public.mdi_audit_retention(p_tenant_id uuid)
returns jsonb language sql stable set search_path=public as $$
select jsonb_build_object('tenant_id',p_tenant_id,'overdue_subjects',
 (select count(*) from mdi_subject_tenants st join mdi_subjects s on s.id=st.subject_id where st.tenant_id=p_tenant_id and s.last_seen < now()-interval '365 days'))
$$;

create or replace function public.mdi_audit_lawful_basis(p_tenant_id uuid)
returns jsonb language sql stable set search_path=public as $$
select jsonb_build_object('tenant_id',p_tenant_id,'subjects_without_basis',
 (select count(*) from mdi_subject_tenants st left join mdi_lawful_basis_log l on l.tenant_id=st.tenant_id and l.subject_id=st.subject_id and (l.expires_at is null or l.expires_at>now()) where st.tenant_id=p_tenant_id and l.id is null))
$$;

create or replace function public.mdi_audit_cross_border(p_tenant_id uuid)
returns jsonb language sql stable set search_path=public as $$
select jsonb_build_object('tenant_id',p_tenant_id,'cross_border_payments',
 (select count(*) from mdi_payments where tenant_id=p_tenant_id and country_from is distinct from country_to))
$$;

create or replace function public.mdi_dsar_sla_breach(p_tenant_id uuid)
returns jsonb language sql stable set search_path=public as $$
select jsonb_build_object('tenant_id',p_tenant_id,'breaches',
 (select count(*) from mdi_dsar_requests where tenant_id=p_tenant_id and status not in('completed','rejected') and sla_deadline<now()))
$$;

create index if not exists mdi_payments_subject_idx on public.mdi_payments(subject_id,occurred_at desc);
create index if not exists mdi_crypto_tx_wallet_time on public.mdi_crypto_tx(from_wallet,to_wallet,occurred_at desc);
create index if not exists mdi_compliance_tenant_time on public.mdi_compliance_findings(tenant_id,detected_at desc);
create index if not exists mdi_lawful_tenant_time on public.mdi_lawful_basis_log(tenant_id,created_at desc);
create index if not exists mdi_dsar_tenant_time on public.mdi_dsar_requests(tenant_id,created_at desc);

do $$
declare r record;
begin
 for r in select unnest(array[
  'mdi_rf_observations','mdi_rf_trusted','mdi_rf_threats','mdi_wifi_probe_clusters','mdi_ss7_events','mdi_ss7_risk',
  'mdi_a2p_brands','mdi_a2p_aliases','mdi_a2p_routes','mdi_a2p_nonces','mdi_otp_sessions','mdi_wallet_accounts','mdi_wallet_tx',
  'mdi_shared_signals','mdi_payments','mdi_high_risk_corridors','mdi_payment_scores','mdi_crypto_wallets','mdi_crypto_tx','mdi_crypto_exposure',
  'mdi_sanctions_entities','mdi_sanctions_hits','mdi_sar_reports','mdi_legal_requests','mdi_legal_playbooks','mdi_notices','mdi_freeze_orders',
  'mdi_evidence_packs','mdi_response_actions','mdi_compliance_rules','mdi_compliance_findings','mdi_lawful_basis_log','mdi_dsar_requests',
  'mdi_embeddings','mdi_copilot_threads','mdi_copilot_messages'
 ]) t(name)
 loop execute format('alter table public.%I enable row level security',r.name); end loop;
end $$;

revoke all on public.mdi_rf_observations,public.mdi_rf_trusted,public.mdi_rf_threats,public.mdi_wifi_probe_clusters,
 public.mdi_ss7_events,public.mdi_ss7_risk,public.mdi_a2p_brands,public.mdi_a2p_aliases,public.mdi_a2p_routes,public.mdi_a2p_nonces,
 public.mdi_otp_sessions,public.mdi_wallet_accounts,public.mdi_wallet_tx,public.mdi_shared_signals,public.mdi_payments,public.mdi_high_risk_corridors,
 public.mdi_payment_scores,public.mdi_crypto_wallets,public.mdi_crypto_tx,public.mdi_crypto_exposure,public.mdi_sanctions_entities,public.mdi_sanctions_hits,
 public.mdi_sar_reports,public.mdi_legal_requests,public.mdi_legal_playbooks,public.mdi_notices,public.mdi_freeze_orders,public.mdi_evidence_packs,
 public.mdi_response_actions,public.mdi_compliance_rules,public.mdi_compliance_findings,public.mdi_lawful_basis_log,public.mdi_dsar_requests,
 public.mdi_embeddings,public.mdi_copilot_threads,public.mdi_copilot_messages from anon,authenticated;

commit;