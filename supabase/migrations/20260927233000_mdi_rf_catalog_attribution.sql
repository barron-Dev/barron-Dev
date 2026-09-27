begin;

-- MDI RF catalog + attribution expansion.
-- This migration adds registries and evidence structures only.
-- It deliberately does not seed unverified hardware/actor claims and does not
-- create external-provider credentials. Live records must arrive from the
-- declared source pipelines.

create table if not exists public.mdi_rf_fingerprint_catalog (
  id uuid primary key default gen_random_uuid(),
  manufacturer text not null,
  product_line text,
  model text,
  country char(3),
  standards text[] not null default '{}',
  bands text[] not null default '{}',
  detection_indicators text[] not null default '{}',
  source_urls text[] not null default '{}',
  source_kind text not null check (source_kind in ('regulator','academic','public_catalog','vendor_spec','community')),
  source_version text,
  validated_at timestamptz,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create unique index if not exists mdi_rf_catalog_identity_idx
  on public.mdi_rf_fingerprint_catalog (manufacturer, coalesce(product_line,''), coalesce(model,''));

create index if not exists mdi_rf_catalog_manufacturer_idx
  on public.mdi_rf_fingerprint_catalog(manufacturer);
create index if not exists mdi_rf_catalog_standards_idx
  on public.mdi_rf_fingerprint_catalog using gin(standards);

create table if not exists public.mdi_band_plan (
  band text primary key,
  rat text not null check (rat in ('GSM','UMTS','LTE','NR')),
  duplex text check (duplex in ('FDD','TDD','SDL','SUL')),
  ul_low_mhz numeric(10,3),
  ul_high_mhz numeric(10,3),
  dl_low_mhz numeric(10,3),
  dl_high_mhz numeric(10,3),
  arfcn_min bigint,
  arfcn_max bigint,
  arfcn_step_khz numeric(8,3),
  arfcn_offset bigint,
  region text[] not null default '{}',
  source_url text not null,
  updated_at timestamptz not null default now()
);

-- Verified LTE/NR reference rows. Frequency/channel ranges are reference data,
-- not observations or detections.
insert into public.mdi_band_plan
  (band,rat,duplex,ul_low_mhz,ul_high_mhz,dl_low_mhz,dl_high_mhz,
   arfcn_min,arfcn_max,arfcn_step_khz,arfcn_offset,region,source_url)
values
 ('B1','LTE','FDD',1920,1980,2110,2170,0,599,100,0,ARRAY['EU','ASIA','MEA','GLOBAL'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('B3','LTE','FDD',1710,1785,1805,1880,1200,1949,100,1200,ARRAY['EU','ASIA','MEA','GLOBAL'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('B7','LTE','FDD',2500,2570,2620,2690,2750,3449,100,2750,ARRAY['EU','ASIA','GLOBAL'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('B8','LTE','FDD',880,915,925,960,3450,3799,100,3450,ARRAY['EU','MEA','ASIA','GLOBAL'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('B20','LTE','FDD',832,862,791,821,6150,6449,100,6150,ARRAY['EU','MEA'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('B28','LTE','FDD',703,748,758,803,9210,9659,100,9210,ARRAY['EU','ASIA','MEA'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('B41','LTE','TDD',2496,2690,2496,2690,39650,41589,100,39650,ARRAY['US','ASIA','MEA'],'https://www.etsi.org/deliver/etsi_ts/136100_136199/136101/'),
 ('n1','NR','FDD',1920,1980,2110,2170,422000,434000,100,422000,ARRAY['EU','ASIA','MEA','GLOBAL'],'https://www.3gpp.org/ftp/Specs/archive/38_series/38.104/'),
 ('n3','NR','FDD',1710,1785,1805,1880,361000,376000,100,361000,ARRAY['EU','ASIA','MEA','GLOBAL'],'https://www.3gpp.org/ftp/Specs/archive/38_series/38.104/'),
 ('n28','NR','FDD',703,748,758,803,151600,160600,100,151600,ARRAY['EU','ASIA','MEA'],'https://www.3gpp.org/ftp/Specs/archive/38_series/38.104/'),
 ('n41','NR','TDD',2496,2690,2496,2690,499200,537999,15,499200,ARRAY['US','ASIA','MEA'],'https://www.3gpp.org/ftp/Specs/archive/38_series/38.104/'),
 ('n78','NR','TDD',3300,3800,3300,3800,620000,653333,15,620000,ARRAY['EU','ASIA','MEA','GLOBAL'],'https://www.3gpp.org/ftp/Specs/archive/38_series/38.104/')
on conflict (band) do update set
  rat=excluded.rat, duplex=excluded.duplex, ul_low_mhz=excluded.ul_low_mhz,
  ul_high_mhz=excluded.ul_high_mhz, dl_low_mhz=excluded.dl_low_mhz,
  dl_high_mhz=excluded.dl_high_mhz, arfcn_min=excluded.arfcn_min,
  arfcn_max=excluded.arfcn_max, arfcn_step_khz=excluded.arfcn_step_khz,
  arfcn_offset=excluded.arfcn_offset, region=excluded.region,
  source_url=excluded.source_url, updated_at=now();

create or replace function public.mdi_validate_arfcn(p_rat text, p_arfcn bigint)
returns table(band text, valid boolean, freq_mhz numeric, reason text)
language sql stable set search_path=public as $$
with matches as (
  select b.band,
    case
      when b.rat='LTE' then b.dl_low_mhz + ((p_arfcn-b.arfcn_offset)::numeric * 0.1)
      when b.rat='NR' and p_arfcn < 600000 then p_arfcn::numeric * 0.005
      when b.rat='NR' and p_arfcn < 2016667 then 3000 + (p_arfcn-600000)::numeric * 0.015
      when b.rat='NR' then 24250 + (p_arfcn-2016667)::numeric * 0.06
      else null
    end as freq_mhz
  from public.mdi_band_plan b
  where b.rat=p_rat and p_arfcn between b.arfcn_min and b.arfcn_max
)
select m.band,true,m.freq_mhz,'reference_range_match'
from matches m
order by m.band
limit 1
union all
select null,false,null,'arfcn_not_in_reference_range'
where not exists (select 1 from matches);
$$;

create table if not exists public.mdi_attack_mobile (
  technique_id text primary key,
  name text not null,
  tactic text not null,
  description text,
  platforms text[] not null default ARRAY['Android','iOS'],
  source_url text not null,
  source_version text,
  updated_at timestamptz not null default now()
);

-- Verified current Mobile ATT&CK identifiers used by this service.
insert into public.mdi_attack_mobile
  (technique_id,name,tactic,description,source_url)
values
 ('T1451','SIM Card Swap','Initial Access',
  'Transfer of a victim phone number to an adversary-controlled SIM or device.',
  'https://attack.mitre.org/techniques/T1451/'),
 ('T1655','Masquerading','Defense Evasion',
  'Manipulation of artifact identity or appearance to appear legitimate.',
  'https://attack.mitre.org/techniques/T1655/'),
 ('T1636','Protected User Data','Collection',
  'Collection of permission-backed protected mobile user data.',
  'https://attack.mitre.org/techniques/T1636/'),
 ('T1636.004','Protected User Data: SMS Messages','Collection',
  'Collection of SMS messages from a mobile device.',
  'https://attack.mitre.org/techniques/T1636/004/'),
 ('T1437','Application Layer Protocol','Command and Control',
  'Use of application-layer protocols for communications.',
  'https://attack.mitre.org/techniques/T1437/'),
 ('T1474','Supply Chain Compromise','Initial Access',
  'Compromise introduced through products or delivery mechanisms.',
  'https://attack.mitre.org/techniques/T1474/')
on conflict (technique_id) do update set
  name=excluded.name,tactic=excluded.tactic,description=excluded.description,
  source_url=excluded.source_url,updated_at=now();

create table if not exists public.mdi_threat_actors (
  id uuid primary key default gen_random_uuid(),
  actor_id text not null unique,
  name text not null,
  aliases text[] not null default '{}',
  origin_country char(2),
  motivation text,
  sophistication text,
  first_seen timestamptz,
  last_seen timestamptz,
  target_sectors text[] not null default '{}',
  target_countries char(2)[] not null default '{}',
  sources text[] not null default '{}',
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.mdi_actor_ttps (
  id bigserial primary key,
  actor_id uuid not null references public.mdi_threat_actors(id) on delete cascade,
  technique_id text not null references public.mdi_attack_mobile(technique_id),
  confidence numeric(4,3) not null check(confidence between 0 and 1),
  first_observed timestamptz,
  last_observed timestamptz,
  source text not null,
  evidence jsonb not null default '{}',
  unique(actor_id,technique_id)
);
create index if not exists mdi_actor_ttps_actor_idx on public.mdi_actor_ttps(actor_id);
create index if not exists mdi_actor_ttps_tech_idx on public.mdi_actor_ttps(technique_id);

create table if not exists public.mdi_case_ttps (
  id bigserial primary key,
  case_id uuid not null references public.crime_cases(id) on delete cascade,
  technique_id text not null references public.mdi_attack_mobile(technique_id),
  observed_at timestamptz not null default now(),
  confidence numeric(4,3) not null check(confidence between 0 and 1),
  evidence_ref text,
  detector text not null,
  raw jsonb not null default '{}'
);
create index if not exists mdi_case_ttps_case_idx on public.mdi_case_ttps(case_id,observed_at desc);
create unique index if not exists mdi_case_ttps_dedupe_idx
  on public.mdi_case_ttps(case_id,technique_id,detector,evidence_ref)
  where evidence_ref is not null;

create table if not exists public.mdi_attribution (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.crime_cases(id) on delete cascade,
  actor_id uuid references public.mdi_threat_actors(id) on delete set null,
  confidence numeric(4,3) not null check(confidence between 0 and 1),
  method text not null,
  evidence jsonb not null default '{}',
  alternative_actors jsonb not null default '[]',
  computed_at timestamptz not null default now()
);
create index if not exists mdi_attr_case_idx on public.mdi_attribution(case_id,computed_at desc);

create or replace function public.mdi_attribute_by_ttp(p_case uuid)
returns table(actor_id text,actor_name text,jaccard numeric,shared_ttps text[],confidence numeric)
language sql stable set search_path=public as $$
with case_ttps as (
  select distinct technique_id from public.mdi_case_ttps where case_id=p_case
),
actor_sets as (
  select a.id,a.actor_id,a.name,array_agg(distinct t.technique_id) ttps
  from public.mdi_threat_actors a
  join public.mdi_actor_ttps t on t.actor_id=a.id
  group by a.id,a.actor_id,a.name
),
scores as (
  select s.*,
    array(select unnest(s.ttps) intersect select technique_id from case_ttps) shared,
    (select count(*) from (select unnest(s.ttps) intersect select technique_id from case_ttps) q)::numeric inter_n,
    (select count(*) from (select unnest(s.ttps) union select technique_id from case_ttps) q)::numeric union_n
  from actor_sets s
)
select actor_id, name,
  case when union_n=0 then 0 else inter_n/union_n end,
  shared,
  least(1,case when union_n=0 then 0 else inter_n/union_n end)
from scores
where inter_n>0
order by 3 desc
limit 10;
$$;

-- Service-only registries. Customer access is through authenticated Cyclothone
-- server routes; no direct anon/authenticated table access is granted.
alter table public.mdi_rf_fingerprint_catalog enable row level security;
alter table public.mdi_band_plan enable row level security;
alter table public.mdi_attack_mobile enable row level security;
alter table public.mdi_threat_actors enable row level security;
alter table public.mdi_actor_ttps enable row level security;
alter table public.mdi_case_ttps enable row level security;
alter table public.mdi_attribution enable row level security;

revoke all on public.mdi_rf_fingerprint_catalog,public.mdi_band_plan,
  public.mdi_attack_mobile,public.mdi_threat_actors,public.mdi_actor_ttps,
  public.mdi_case_ttps,public.mdi_attribution from anon,authenticated;

drop policy if exists mdi_rf_catalog_service on public.mdi_rf_fingerprint_catalog;
create policy mdi_rf_catalog_service on public.mdi_rf_fingerprint_catalog
  for all to service_role using(true) with check(true);
drop policy if exists mdi_band_plan_service on public.mdi_band_plan;
create policy mdi_band_plan_service on public.mdi_band_plan
  for all to service_role using(true) with check(true);
drop policy if exists mdi_attack_mobile_service on public.mdi_attack_mobile;
create policy mdi_attack_mobile_service on public.mdi_attack_mobile
  for all to service_role using(true) with check(true);
drop policy if exists mdi_threat_actors_service on public.mdi_threat_actors;
create policy mdi_threat_actors_service on public.mdi_threat_actors
  for all to service_role using(true) with check(true);
drop policy if exists mdi_actor_ttps_service on public.mdi_actor_ttps;
create policy mdi_actor_ttps_service on public.mdi_actor_ttps
  for all to service_role using(true) with check(true);
drop policy if exists mdi_case_ttps_service on public.mdi_case_ttps;
create policy mdi_case_ttps_service on public.mdi_case_ttps
  for all to service_role using(true) with check(true);
drop policy if exists mdi_attribution_service on public.mdi_attribution;
create policy mdi_attribution_service on public.mdi_attribution
  for all to service_role using(true) with check(true);

revoke all on function public.mdi_validate_arfcn(text,bigint) from public;
grant execute on function public.mdi_validate_arfcn(text,bigint) to service_role;
revoke all on function public.mdi_attribute_by_ttp(uuid) from public;
grant execute on function public.mdi_attribute_by_ttp(uuid) to service_role;

commit;
