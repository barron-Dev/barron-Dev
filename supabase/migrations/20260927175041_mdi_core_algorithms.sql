begin;
-- MDI core schema + algorithms. Applied to production as 20260927175041_mdi_core_algorithms.
create extension if not exists pgcrypto;
create extension if not exists pg_trgm;
create extension if not exists cube;
create extension if not exists earthdistance;

do $$ begin create type public.mdi_provider_kind as enum('camara','aggregator','carrier_direct','osint','satellite','internal','lawful'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_capability as enum('number_verify','carrier_lookup','line_type','sim_swap','port_history','device_reachability','device_identity','location_verify','location_retrieve','roaming','kyc_match','sms_deliverability','tac_lookup','number_reputation','tle_catalog','orbit_propagate','imagery','gnss_interference','sat_comms'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_subject_kind as enum('msisdn','imei','imsi','iccid','mac','ip','email','device_fp','satellite','ground_station','person','org','wallet','case','geo_cell'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_edge_kind as enum('called','called_by','messaged','messaged_by','registered_on','roamed_on','served_by_cell','co_located','shared_device','shared_sim','shared_imei','owned_by','associated_with','paid','mentioned','imaged','overflew'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_risk_band as enum('unknown','low','medium','high','critical'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_source_class as enum('carrier_api','regulator','osint','user_report','honeypot','sensor','satellite','internal_graph','partner_share'); exception when duplicate_object then null; end $$;

create table if not exists public.mdi_providers(
 id uuid primary key default gen_random_uuid(),slug text unique not null,name text not null,kind public.mdi_provider_kind not null,
 capabilities public.mdi_capability[] not null default '{}',coverage jsonb not null default '{}',base_url text,auth_mode text not null default 'vault_secret',
 secret_ref text,weight numeric(5,4) not null default 1,rate_limit_per_min int not null default 60,cost_micros bigint not null default 0,
 timeout_ms int not null default 8000,status text not null default 'active' check(status in('active','degraded','disabled')),
 created_at timestamptz not null default now(),updated_at timestamptz not null default now());
create table if not exists public.mdi_operators(
 id uuid primary key default gen_random_uuid(),mcc char(3) not null,mnc char(3) not null,name text not null,country_iso2 char(2) not null,
 brand text,is_mno boolean not null default true,is_mvno boolean not null default false,host_mcc char(3),host_mnc char(3),
 camara_ready boolean not null default false,metadata jsonb not null default '{}',unique(mcc,mnc));
create index if not exists mdi_operators_country_idx on public.mdi_operators(country_iso2);

create table if not exists public.mdi_subjects(
 id uuid primary key default gen_random_uuid(),kind public.mdi_subject_kind not null,canonical text not null,display text,country_iso2 char(2),
 operator_id uuid references public.mdi_operators(id) on delete set null,risk_score numeric(5,2) not null default 0 check(risk_score between 0 and 100),
 risk_band public.mdi_risk_band not null default 'unknown',confidence numeric(4,3) not null default .5 check(confidence between 0 and 1),
 first_seen timestamptz not null default now(),last_seen timestamptz not null default now(),attributes jsonb not null default '{}',
 pii_grade smallint not null default 0 check(pii_grade between 0 and 3),unique(kind,canonical));
create index if not exists mdi_subjects_kind_band_idx on public.mdi_subjects(kind,risk_band);
create index if not exists mdi_subjects_display_trgm on public.mdi_subjects using gin(display extensions.gin_trgm_ops);
create index if not exists mdi_subjects_attrs_gin on public.mdi_subjects using gin(attributes jsonb_path_ops);
create table if not exists public.mdi_subject_aliases(id uuid primary key default gen_random_uuid(),subject_id uuid not null references public.mdi_subjects(id) on delete cascade,alias text not null,alias_kind text not null,created_at timestamptz not null default now(),unique(subject_id,alias));

create table if not exists public.mdi_number_intel(
 subject_id uuid primary key references public.mdi_subjects(id) on delete cascade,e164 text not null,country_iso2 char(2),calling_code text,national_number text,line_type text,
 is_valid boolean,is_portable boolean,ported_at timestamptz,carrier_name text,mcc char(3),mnc char(3),original_carrier text,roaming boolean,reachable boolean,
 risk_flags text[] not null default '{}',raw jsonb not null default '{}',updated_at timestamptz not null default now());
create table if not exists public.mdi_carrier_events(
 id uuid primary key default gen_random_uuid(),subject_id uuid not null references public.mdi_subjects(id) on delete cascade,event_type text not null check(event_type in('sim_swap','sim_activate','sim_deactivate','port_out','port_in','msisdn_recycle','imei_change','suspend','restore','roaming_on','roaming_off','esim_download','number_verify')),
 occurred_at timestamptz not null,from_operator uuid references public.mdi_operators(id),to_operator uuid references public.mdi_operators(id),from_iccid text,to_iccid text,from_imei text,to_imei text,
 source public.mdi_source_class not null default 'carrier_api',provider_id uuid references public.mdi_providers(id),confidence numeric(4,3) not null default .8,evidence_ref text,raw jsonb not null default '{}',created_at timestamptz not null default now());
create index if not exists mdi_carrier_events_subj_time on public.mdi_carrier_events(subject_id,occurred_at desc);
create index if not exists mdi_carrier_events_type_time on public.mdi_carrier_events(event_type,occurred_at desc);

create table if not exists public.mdi_imei_tac(tac char(8) primary key,brand text,model text,marketing_name text,device_type text,os_family text,release_year int,dual_sim boolean,sat_capable boolean default false,bands text[],source text default 'gsma_imei_db');
create table if not exists public.mdi_device_intel(
 subject_id uuid primary key references public.mdi_subjects(id) on delete cascade,imei char(15),imei_sv char(2),tac char(8) references public.mdi_imei_tac(tac),serial text,brand text,model text,device_type text,os text,os_version text,first_seen timestamptz,last_seen timestamptz,reachable boolean,roaming boolean,sim_count int default 0,risk_flags text[] not null default '{}',raw jsonb not null default '{}',updated_at timestamptz not null default now());

create table if not exists public.mdi_comms_events(
 id uuid primary key default gen_random_uuid(),channel text not null check(channel in('voice','sms','mms','rcs','ussd','data','sat_voice')),direction text check(direction in('mo','mt','unknown')),
 a_subject_id uuid references public.mdi_subjects(id) on delete set null,b_subject_id uuid references public.mdi_subjects(id) on delete set null,a_raw text,b_raw text,started_at timestamptz not null,duration_s int,msg_hash text,msg_excerpt text,
 threat_labels text[] not null default '{}',spam_score numeric(5,2),source public.mdi_source_class not null,case_id uuid,evidence_ref text,raw jsonb not null default '{}',created_at timestamptz not null default now());
create index if not exists mdi_comms_a_time on public.mdi_comms_events(a_subject_id,started_at desc);
create index if not exists mdi_comms_b_time on public.mdi_comms_events(b_subject_id,started_at desc);
create index if not exists mdi_comms_labels on public.mdi_comms_events using gin(threat_labels);
create table if not exists public.mdi_caller_reports(
 id uuid primary key default gen_random_uuid(),subject_id uuid not null references public.mdi_subjects(id) on delete cascade,reporter_hash text,category text not null,severity smallint not null default 1 check(severity between 1 and 5),narrative text,occurred_at timestamptz not null default now(),verified boolean not null default false,created_at timestamptz not null default now());
create index if not exists mdi_caller_reports_subj on public.mdi_caller_reports(subject_id,occurred_at desc);

create table if not exists public.mdi_location_signals(
 id uuid primary key default gen_random_uuid(),subject_id uuid not null references public.mdi_subjects(id) on delete cascade,signal_type text not null check(signal_type in('cell_id','ta','nbr_cell','gnss','wifi_bssid','ip_geo','timing_advance','otdoa','sat_gnss','network_verify')),
 lat double precision,lon double precision,radius_m int,altitude_m double precision,h3_r7 text,h3_r9 text,mcc char(3),mnc char(3),lac text,cid text,observed_at timestamptz not null,confidence numeric(4,3) not null default .5,source public.mdi_source_class not null,provider_id uuid references public.mdi_providers(id),case_id uuid,raw jsonb not null default '{}',created_at timestamptz not null default now());
create index if not exists mdi_loc_subj_time on public.mdi_location_signals(subject_id,observed_at desc);
create index if not exists mdi_loc_geo on public.mdi_location_signals using gist(ll_to_earth(lat,lon)) where lat is not null and lon is not null;
create table if not exists public.mdi_geofences(id uuid primary key default gen_random_uuid(),name text not null,kind text not null default 'circle' check(kind in('circle','polygon','corridor')),center_lat double precision,center_lon double precision,radius_m int,polygon jsonb,active_from timestamptz default now(),active_to timestamptz,case_id uuid,created_by uuid,created_at timestamptz not null default now());

create table if not exists public.mdi_satellites(norad_id int primary key,name text not null,intl_designator text,operator text,country char(2),purpose text,is_imaging boolean default false,is_sar boolean default false,is_comms boolean default false,tle_line1 text,tle_line2 text,epoch timestamptz,inclination numeric(7,4),raan numeric(7,4),eccentricity numeric(9,8),argp numeric(7,4),mean_anomaly numeric(7,4),mean_motion numeric(11,8),bstar numeric(12,8),updated_at timestamptz not null default now());
create index if not exists mdi_sat_purpose on public.mdi_satellites(purpose) where purpose is not null;
create table if not exists public.mdi_satellite_passes(id bigserial primary key,norad_id int not null references public.mdi_satellites(norad_id) on delete cascade,observer_lat double precision not null,observer_lon double precision not null,observer_alt_m int not null default 0,aos timestamptz not null,los timestamptz not null,tca timestamptz not null,max_elevation numeric(6,3) not null,min_range_km numeric(10,3),start_azimuth numeric(6,2),end_azimuth numeric(6,2),sunlit boolean,computed_at timestamptz not null default now());
create index if not exists mdi_passes_norad_aos on public.mdi_satellite_passes(norad_id,aos);
create table if not exists public.mdi_satellite_observations(id uuid primary key default gen_random_uuid(),norad_id int references public.mdi_satellites(norad_id),observation_type text not null check(observation_type in('image','sar','ais','adsb','rf','gnss_interference','thermal','nightlights')),footprint_center_lat double precision,footprint_center_lon double precision,footprint_radius_km numeric(8,2),acquired_at timestamptz not null,asset_url text,asset_sha256 text,cloud_pct numeric(5,2),provider_id uuid references public.mdi_providers(id),case_id uuid,evidence_ref text,metadata jsonb not null default '{}',created_at timestamptz not null default now());
create index if not exists mdi_satobs_time on public.mdi_satellite_observations(acquired_at desc);

create table if not exists public.mdi_graph_edges(id uuid primary key default gen_random_uuid(),src_id uuid not null references public.mdi_subjects(id) on delete cascade,dst_id uuid not null references public.mdi_subjects(id) on delete cascade,kind public.mdi_edge_kind not null,weight numeric(6,4) not null default 1 check(weight between 0 and 1),confidence numeric(4,3) not null default .5 check(confidence between 0 and 1),observations int not null default 1,first_seen timestamptz not null default now(),last_seen timestamptz not null default now(),case_ids uuid[] not null default '{}',evidence_refs text[] not null default '{}',attributes jsonb not null default '{}',unique(src_id,dst_id,kind));
create index if not exists mdi_edges_src on public.mdi_graph_edges(src_id,weight desc);
create index if not exists mdi_edges_dst on public.mdi_graph_edges(dst_id,weight desc);
create table if not exists public.mdi_correlations(id uuid primary key default gen_random_uuid(),correlation_type text not null,subject_ids uuid[] not null,edge_ids uuid[] not null default '{}',strength numeric(5,4) not null check(strength between 0 and 1),p_value numeric(8,6),algorithm text not null,explanation jsonb not null default '{}',case_id uuid,created_at timestamptz not null default now());
create index if not exists mdi_corr_subjects on public.mdi_correlations using gin(subject_ids);
create table if not exists public.mdi_risk_assessments(id uuid primary key default gen_random_uuid(),subject_id uuid not null references public.mdi_subjects(id) on delete cascade,score numeric(5,2) not null check(score between 0 and 100),band public.mdi_risk_band not null,prior numeric(5,4) not null,log_odds numeric(10,4) not null,signals jsonb not null,model_version text not null default 'mdi-risk-v1',computed_at timestamptz not null default now());
create index if not exists mdi_risk_subj_time on public.mdi_risk_assessments(subject_id,computed_at desc);
create table if not exists public.mdi_provider_calls(id bigserial primary key,provider_id uuid references public.mdi_providers(id),capability public.mdi_capability not null,subject_id uuid references public.mdi_subjects(id) on delete set null,request_hash text not null,cache_hit boolean not null default false,ok boolean not null,http_status int,latency_ms int,cost_micros bigint not null default 0,error_code text,case_id uuid,actor_id uuid,called_at timestamptz not null default now());
create index if not exists mdi_pcalls_hash on public.mdi_provider_calls(request_hash,called_at desc);
create index if not exists mdi_pcalls_provider_time on public.mdi_provider_calls(provider_id,called_at desc);
create table if not exists public.mdi_case_links(id uuid primary key default gen_random_uuid(),case_id uuid not null,subject_id uuid references public.mdi_subjects(id) on delete cascade,edge_id uuid references public.mdi_graph_edges(id) on delete cascade,correlation_id uuid references public.mdi_correlations(id) on delete cascade,role text not null default 'related',added_by uuid,added_at timestamptz not null default now());
create index if not exists mdi_case_links_case on public.mdi_case_links(case_id);

create or replace function public.mdi_e164(p_raw text,p_default_cc text default null) returns text language plpgsql immutable as $$
declare v text;cc text;begin if p_raw is null then return null;end if;v:=regexp_replace(p_raw,'[^0-9+]','','g');if v='' then return null;end if;if left(v,2)='00' then v:='+'||substr(v,3);end if;if left(v,1)<>'+' then cc:=coalesce(p_default_cc,'');if cc='' then return null;end if;v:='+'||regexp_replace(cc,'[^0-9]','','g')||regexp_replace(v,'^0+','','');end if;if length(regexp_replace(v,'[^0-9]','','g')) not between 7 and 15 then return null;end if;return v;end $$;
create or replace function public.mdi_luhn_ok(p_digits text) returns boolean language plpgsql immutable as $$
declare d int;i int;s int:=0;n int;alt boolean:=false;begin n:=length(p_digits);if n=0 or p_digits!~'^[0-9]+$' then return false;end if;for i in reverse n..1 loop d:=substr(p_digits,i,1)::int;if alt then d:=d*2;if d>9 then d:=d-9;end if;end if;s:=s+d;alt:=not alt;end loop;return s%10=0;end $$;
create or replace function public.mdi_imei_valid(p_imei text) returns boolean language sql immutable as $$select length(regexp_replace(p_imei,'[^0-9]','','g'))=15 and public.mdi_luhn_ok(regexp_replace(p_imei,'[^0-9]','','g'));$$;
create or replace function public.mdi_imei_tac(p_imei text) returns char(8) language sql immutable as $$select left(regexp_replace(p_imei,'[^0-9]','','g'),8)::char(8);$$;
create or replace function public.mdi_decay(p_age_seconds numeric,p_half_life_seconds numeric) returns numeric language sql immutable as $$select case when p_half_life_seconds is null or p_half_life_seconds<=0 then 1::numeric else power(.5::numeric,greatest(p_age_seconds,0)/p_half_life_seconds) end;$$;

create or replace function public.mdi_risk_from_signals(p_prior numeric,p_signals jsonb,out score numeric,out band public.mdi_risk_band,out log_odds numeric,out breakdown jsonb)
returns record language plpgsql immutable as $$
declare s jsonb;lr numeric;w numeric;c numeric;a numeric;hl numeric;elr numeric;lo numeric;pr numeric;begin
 p_prior:=least(greatest(p_prior,.000001),.999999);lo:=ln(p_prior/(1-p_prior));breakdown:='[]';
 for s in select * from jsonb_array_elements(coalesce(p_signals,'[]')) loop
  lr:=coalesce((s->>'lr')::numeric,1);w:=coalesce((s->>'w')::numeric,1);c:=least(greatest(coalesce((s->>'conf')::numeric,1),0),1);a:=coalesce((s->>'age_s')::numeric,0);hl:=coalesce((s->>'half_life_s')::numeric,0);
  elr:=greatest(1+(lr-1)*c*public.mdi_decay(a,hl),.0001);lo:=lo+w*ln(elr);breakdown:=breakdown||jsonb_build_object('k',s->>'k','lr',lr,'eff_lr',round(elr,4),'contrib',round(w*ln(elr),4));
 end loop;pr:=1/(1+exp(-lo));score:=round(pr*100,2);log_odds:=round(lo,4);band:=case when pr>=.9 then 'critical' when pr>=.7 then 'high' when pr>=.4 then 'medium' when pr>=.1 then 'low' else 'unknown' end;return;end $$;

create or replace function public.mdi_upsert_subject(p_kind public.mdi_subject_kind,p_canonical text,p_display text default null,p_country char(2) default null,p_attrs jsonb default '{}',p_pii smallint default 0)
returns uuid language plpgsql set search_path=public as $$
declare id uuid;begin insert into public.mdi_subjects(kind,canonical,display,country_iso2,attributes,pii_grade,last_seen) values(p_kind,p_canonical,p_display,p_country,coalesce(p_attrs,'{}'),p_pii,now()) on conflict(kind,canonical) do update set last_seen=now(),display=coalesce(excluded.display,public.mdi_subjects.display),attributes=public.mdi_subjects.attributes||excluded.attributes returning public.mdi_subjects.id into id;return id;end $$;

create or replace function public.mdi_link(p_src uuid,p_dst uuid,p_kind public.mdi_edge_kind,p_weight numeric default 1,p_conf numeric default .5,p_case uuid default null,p_evidence text default null,p_attrs jsonb default '{}')
returns uuid language plpgsql set search_path=public as $$
declare id uuid;begin insert into public.mdi_graph_edges(src_id,dst_id,kind,weight,confidence,case_ids,evidence_refs,attributes) values(p_src,p_dst,p_kind,least(greatest(p_weight,0),1),least(greatest(p_conf,0),1),case when p_case is null then '{}' else array[p_case] end,case when p_evidence is null then '{}' else array[p_evidence] end,coalesce(p_attrs,'{}')) on conflict(src_id,dst_id,kind) do update set weight=round(public.mdi_graph_edges.weight*.75+excluded.weight*.25,4),confidence=greatest(public.mdi_graph_edges.confidence,excluded.confidence),observations=public.mdi_graph_edges.observations+1,last_seen=now(),case_ids=(select array(select distinct unnest(public.mdi_graph_edges.case_ids||excluded.case_ids))),evidence_refs=(select array(select distinct unnest(public.mdi_graph_edges.evidence_refs||excluded.evidence_refs))),attributes=public.mdi_graph_edges.attributes||excluded.attributes returning public.mdi_graph_edges.id into id;return id;end $$;

create or replace function public.mdi_shortest_path(p_from uuid,p_to uuid,p_max_depth int default 4,p_min_weight numeric default .05)
returns table(depth int,path uuid[],kinds text[],total_cost numeric) language sql stable as $$
with recursive w(depth,path,kinds,cost,node) as(select 0,array[p_from],array[]::text[],0::numeric,p_from union all select w.depth+1,w.path||e.dst_id,w.kinds||e.kind::text,w.cost+1/greatest(e.weight*e.confidence,.001),e.dst_id from w join public.mdi_graph_edges e on e.src_id=w.node where w.depth<p_max_depth and not e.dst_id=any(w.path) and e.weight>=p_min_weight) select depth,path,kinds,round(cost,4) from w where node=p_to order by cost limit 10;$$;

create or replace function public.mdi_neighborhood(p_subject uuid,p_hops int default 2,p_min_weight numeric default .05)
returns table(subject_id uuid,kind public.mdi_subject_kind,canonical text,hops int,via text[],path_weight numeric,risk numeric) language sql stable as $$
with recursive n(id,hops,via,pw,path) as(select p_subject,0,array[]::text[],1::numeric,array[p_subject] union all select e.dst_id,n.hops+1,n.via||e.kind::text,n.pw*e.weight*e.confidence,n.path||e.dst_id from n join public.mdi_graph_edges e on e.src_id=n.id where n.hops<p_hops and e.weight>=p_min_weight and not e.dst_id=any(n.path)) select distinct on(n.id)s.id,s.kind,s.canonical,n.hops,n.via,round(n.pw,4),s.risk_score from n join public.mdi_subjects s on s.id=n.id where n.hops>0 order by n.id,n.pw desc;$$;

create or replace function public.mdi_haversine_m(lat1 double precision,lon1 double precision,lat2 double precision,lon2 double precision) returns double precision language sql immutable as $$select 6371008.8*2*asin(sqrt(power(sin(radians(lat2-lat1)/2),2)+cos(radians(lat1))*cos(radians(lat2))*power(sin(radians(lon2-lon1)/2),2)));$$;
create or replace function public.mdi_point_in_ring(ring jsonb,p_lat double precision,p_lon double precision) returns boolean language plpgsql immutable as $$
declare i int;j int;n int;xi double precision;yi double precision;xj double precision;yj double precision;inside boolean:=false;begin if ring is null or jsonb_typeof(ring)<>'array' then return false;end if;n:=jsonb_array_length(ring);if n<3 then return false;end if;j:=n-1;for i in 0..n-1 loop xi:=(ring->i->>0)::double precision;yi:=(ring->i->>1)::double precision;xj:=(ring->j->>0)::double precision;yj:=(ring->j->>1)::double precision;if((yi>p_lat)<>(yj>p_lat)) and p_lon<(xj-xi)*(p_lat-yi)/nullif(yj-yi,0)+xi then inside:=not inside;end if;j:=i;end loop;return inside;end $$;
create or replace function public.mdi_geofence_hit(p_fence uuid,p_lat double precision,p_lon double precision) returns boolean language plpgsql stable as $$
declare f public.mdi_geofences;begin select * into f from public.mdi_geofences where id=p_fence;if not found then return false;end if;if f.kind='circle' then return public.mdi_haversine_m(f.center_lat,f.center_lon,p_lat,p_lon)<=f.radius_m;end if;if f.kind='polygon' then return public.mdi_point_in_ring(f.polygon->'coordinates'->0,p_lat,p_lon);end if;return false;end $$;

create or replace function public.mdi_refresh_risk(p_subject uuid) returns public.mdi_risk_assessments language plpgsql set search_path=public as $$
declare s public.mdi_subjects;sig jsonb:='[]';prior numeric:=.02;risk public.mdi_risk_assessments;now_ts timestamptz:=now();e record;r record;imeis int;bad numeric;begin
 select * into s from public.mdi_subjects where id=p_subject;if not found then raise exception 'subject % not found',p_subject;end if;
 for e in select occurred_at from public.mdi_carrier_events where subject_id=p_subject and event_type in('sim_swap','port_out','esim_download') order by occurred_at desc limit 5 loop sig:=sig||jsonb_build_object('k','sim_swap','lr',22,'w',1,'conf',.9,'age_s',extract(epoch from(now_ts-e.occurred_at)),'half_life_s',604800);end loop;
 select count(*) c,avg(severity) s,max(occurred_at)m into r from public.mdi_caller_reports where subject_id=p_subject and occurred_at>now_ts-interval '180 days';
 if r.c>0 then sig:=sig||jsonb_build_object('k','caller_reports','lr',1+ln(1+r.c)*coalesce(r.s,1)*.6,'w',1,'conf',least(.5+r.c*.05,.95),'age_s',extract(epoch from(now_ts-r.m)),'half_life_s',2592000);end if;
 if exists(select 1 from public.mdi_number_intel where subject_id=p_subject and line_type='voip') then sig:=sig||jsonb_build_object('k','voip_line','lr',3.5,'w',.8,'conf',.85,'age_s',0,'half_life_s',0);end if;
 if s.kind='msisdn' then select count(distinct dst_id) into imeis from public.mdi_graph_edges where src_id=p_subject and kind in('registered_on','shared_imei');if imeis>=5 then sig:=sig||jsonb_build_object('k','multi_imei','lr',1+imeis*1.4,'w',.9,'conf',least(.4+imeis*.08,.95),'age_s',0,'half_life_s',0);end if;end if;
 select coalesce(sum(e.weight*e.confidence*case x.risk_band when 'critical' then 1 when 'high' then .7 when 'medium' then .35 else .05 end),0) into bad from public.mdi_graph_edges e join public.mdi_subjects x on x.id=e.dst_id where e.src_id=p_subject and x.risk_score>40;
 if bad>.2 then sig:=sig||jsonb_build_object('k','graph_proximity_bad','lr',1+bad*4,'w',.85,'conf',.75,'age_s',0,'half_life_s',0);end if;
 if exists(select 1 from public.mdi_satellite_observations o join public.mdi_case_links cl on cl.case_id=o.case_id where cl.subject_id=p_subject and o.acquired_at>now_ts-interval '24 hours') then sig:=sig||jsonb_build_object('k','satellite_overflight_24h','lr',2.2,'w',.6,'conf',.6,'age_s',0,'half_life_s',0);end if;
 insert into public.mdi_risk_assessments(subject_id,score,band,prior,log_odds,signals) select p_subject,x.score,x.band,prior,x.log_odds,x.breakdown from public.mdi_risk_from_signals(prior,sig) x returning * into risk;
 update public.mdi_subjects set risk_score=risk.score,risk_band=risk.band,confidence=least(.99,.4+jsonb_array_length(sig)*.1),last_seen=now() where id=p_subject;return risk;end $$;

do $$ declare t text; tables text[]:=array['mdi_providers','mdi_operators','mdi_subjects','mdi_subject_aliases','mdi_number_intel','mdi_carrier_events','mdi_imei_tac','mdi_device_intel','mdi_comms_events','mdi_caller_reports','mdi_location_signals','mdi_geofences','mdi_satellites','mdi_satellite_passes','mdi_satellite_observations','mdi_graph_edges','mdi_correlations','mdi_risk_assessments','mdi_provider_calls','mdi_case_links'];begin foreach t in array tables loop execute format('alter table public.%I enable row level security',t);execute format('drop policy if exists %I on public.%I',t||'_service_role',t);execute format('create policy %I on public.%I for all to service_role using(true) with check(true)',t||'_service_role',t);execute format('revoke all on public.%I from anon,authenticated',t);end loop;end $$;
revoke all on function public.mdi_upsert_subject(public.mdi_subject_kind,text,text,char(2),jsonb,smallint) from public,anon,authenticated;
revoke all on function public.mdi_link(uuid,uuid,public.mdi_edge_kind,numeric,numeric,uuid,text,jsonb) from public,anon,authenticated;
revoke all on function public.mdi_refresh_risk(uuid) from public,anon,authenticated;
grant execute on function public.mdi_upsert_subject(public.mdi_subject_kind,text,text,char(2),jsonb,smallint) to service_role;
grant execute on function public.mdi_link(uuid,uuid,public.mdi_edge_kind,numeric,numeric,uuid,text,jsonb) to service_role;
grant execute on function public.mdi_refresh_risk(uuid) to service_role;
commit;