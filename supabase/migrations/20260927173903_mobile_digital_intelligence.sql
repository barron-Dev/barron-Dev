begin;
create extension if not exists pgcrypto;
create extension if not exists pg_trgm;
create extension if not exists cube;
create extension if not exists earthdistance;

do $$ begin create type public.mdi_provider_kind as enum ('camara','aggregator','carrier_direct','osint','satellite','internal','lawful'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_capability as enum ('number_verify','carrier_lookup','line_type','sim_swap','port_history','device_reachability','device_identity','location_verify','location_retrieve','roaming','kyc_match','sms_deliverability','tac_lookup','number_reputation','tle_catalog','orbit_propagate','imagery','gnss_interference','sat_comms'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_subject_kind as enum ('msisdn','imei','imsi','iccid','mac','ip','email','device_fp','satellite','ground_station','person','org','wallet','case','geo_cell'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_edge_kind as enum ('called','called_by','messaged','messaged_by','registered_on','roamed_on','served_by_cell','co_located','shared_device','shared_sim','shared_imei','owned_by','associated_with','paid','mentioned','imaged','overflew'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_risk_band as enum ('unknown','low','medium','high','critical'); exception when duplicate_object then null; end $$;
do $$ begin create type public.mdi_source_class as enum ('carrier_api','regulator','osint','user_report','honeypot','sensor','satellite','internal_graph','partner_share'); exception when duplicate_object then null; end $$;

create table if not exists public.mdi_providers (
 id uuid primary key default gen_random_uuid(), slug text not null unique, name text not null,
 kind public.mdi_provider_kind not null, capabilities public.mdi_capability[] not null default '{}',
 coverage jsonb not null default '{}'::jsonb, base_url text, auth_mode text not null default 'vault_secret',
 secret_ref text, weight numeric(5,4) not null default 1.0, rate_limit_per_min int not null default 60,
 cost_micros bigint not null default 0, timeout_ms int not null default 8000,
 status text not null default 'active' check(status in ('active','degraded','disabled')),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.mdi_operators (
 id uuid primary key default gen_random_uuid(), mcc char(3) not null, mnc char(3) not null, name text not null,
 country_iso2 char(2) not null, brand text, is_mno boolean not null default true, is_mvno boolean not null default false,
 host_mcc char(3), host_mnc char(3), camara_ready boolean not null default false, metadata jsonb not null default '{}'::jsonb,
 unique(mcc,mnc)
);
create index if not exists mdi_operators_country_idx on public.mdi_operators(country_iso2);

create table if not exists public.mdi_subjects (
 id uuid primary key default gen_random_uuid(), kind public.mdi_subject_kind not null, canonical text not null,
 display text, country_iso2 char(2), operator_id uuid references public.mdi_operators(id) on delete set null,
 risk_score numeric(5,2) not null default 0 check(risk_score between 0 and 100),
 risk_band public.mdi_risk_band not null default 'unknown', confidence numeric(4,3) not null default 0.5,
 first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
 attributes jsonb not null default '{}'::jsonb, pii_grade smallint not null default 0, unique(kind,canonical)
);
create index if not exists mdi_subjects_kind_band_idx on public.mdi_subjects(kind,risk_band);
create index if not exists mdi_subjects_display_trgm on public.mdi_subjects using gin(display gin_trgm_ops);
create index if not exists mdi_subjects_attrs_gin on public.mdi_subjects using gin(attributes jsonb_path_ops);
create table if not exists public.mdi_subject_aliases (
 id uuid primary key default gen_random_uuid(), subject_id uuid not null references public.mdi_subjects(id) on delete cascade,
 alias text not null, alias_kind text not null, created_at timestamptz not null default now(), unique(subject_id,alias)
);

create table if not exists public.mdi_number_intel (
 subject_id uuid primary key references public.mdi_subjects(id) on delete cascade, e164 text not null, country_iso2 char(2),
 calling_code text, national_number text, line_type text, is_valid boolean, is_portable boolean, ported_at timestamptz,
 carrier_name text, mcc char(3), mnc char(3), original_carrier text, roaming boolean, reachable boolean,
 risk_flags text[] not null default '{}', raw jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now()
);
create table if not exists public.mdi_carrier_events (
 id uuid primary key default gen_random_uuid(), subject_id uuid not null references public.mdi_subjects(id) on delete cascade,
 event_type text not null check(event_type in('sim_swap','sim_activate','sim_deactivate','port_out','port_in','msisdn_recycle','imei_change','suspend','restore','roaming_on','roaming_off','esim_download','number_verify')),
 occurred_at timestamptz not null, from_operator uuid references public.mdi_operators(id), to_operator uuid references public.mdi_operators(id),
 from_iccid text, to_iccid text, from_imei text, to_imei text, source public.mdi_source_class not null default 'carrier_api',
 provider_id uuid references public.mdi_providers(id), confidence numeric(4,3) not null default 0.8, evidence_ref text,
 raw jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index if not exists mdi_carrier_events_subj_time on public.mdi_carrier_events(subject_id,occurred_at desc);
create index if not exists mdi_carrier_events_type_time on public.mdi_carrier_events(event_type,occurred_at desc);

create table if not exists public.mdi_imei_tac (
 tac char(8) primary key, brand text, model text, marketing_name text, device_type text, os_family text,
 release_year int, dual_sim boolean, sat_capable boolean default false, bands text[], source text default 'gsma_imei_db'
);
create table if not exists public.mdi_device_intel (
 subject_id uuid primary key references public.mdi_subjects(id) on delete cascade, imei char(15), imei_sv char(2),
 tac char(8) references public.mdi_imei_tac(tac), serial text, brand text, model text, device_type text, os text,
 os_version text, first_seen timestamptz, last_seen timestamptz, reachable boolean, roaming boolean, sim_count int default 0,
 risk_flags text[] not null default '{}', raw jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now()
);

create table if not exists public.mdi_comms_events (
 id uuid primary key default gen_random_uuid(), channel text not null check(channel in('voice','sms','mms','rcs','ussd','data','sat_voice')),
 direction text check(direction in('mo','mt','unknown')), a_subject_id uuid references public.mdi_subjects(id) on delete set null,
 b_subject_id uuid references public.mdi_subjects(id) on delete set null, a_raw text, b_raw text, started_at timestamptz not null,
 duration_s int, msg_hash text, msg_excerpt text, threat_labels text[] not null default '{}', spam_score numeric(5,2),
 source public.mdi_source_class not null, case_id uuid, evidence_ref text, raw jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);
create index if not exists mdi_comms_a_time on public.mdi_comms_events(a_subject_id,started_at desc);
create index if not exists mdi_comms_b_time on public.mdi_comms_events(b_subject_id,started_at desc);
create index if not exists mdi_comms_labels on public.mdi_comms_events using gin(threat_labels);
create table if not exists public.mdi_caller_reports (
 id uuid primary key default gen_random_uuid(), subject_id uuid not null references public.mdi_subjects(id) on delete cascade,
 reporter_hash text, category text not null, severity smallint not null default 1 check(severity between 1 and 5),
 narrative text, occurred_at timestamptz not null default now(), verified boolean not null default false, created_at timestamptz not null default now()
);
create index if not exists mdi_caller_reports_subj on public.mdi_caller_reports(subject_id,occurred_at desc);

create table if not exists public.mdi_location_signals (
 id uuid primary key default gen_random_uuid(), subject_id uuid not null references public.mdi_subjects(id) on delete cascade,
 signal_type text not null check(signal_type in('cell_id','ta','nbr_cell','gnss','wifi_bssid','ip_geo','timing_advance','otdoa','sat_gnss','network_verify')),
 lat double precision, lon double precision, radius_m int, altitude_m double precision, h3_r7 text, h3_r9 text,
 mcc char(3), mnc char(3), lac text, cid text, observed_at timestamptz not null, confidence numeric(4,3) not null default 0.5,
 source public.mdi_source_class not null, provider_id uuid references public.mdi_providers(id), case_id uuid, raw jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);
create index if not exists mdi_loc_subj_time on public.mdi_location_signals(subject_id,observed_at desc);
create index if not exists mdi_loc_geo on public.mdi_location_signals using gist(ll_to_earth(lat,lon)) where lat is not null;
create table if not exists public.mdi_geofences (
 id uuid primary key default gen_random_uuid(), name text not null, kind text not null default 'circle' check(kind in('circle','polygon','corridor')),
 center_lat double precision, center_lon double precision, radius_m int, polygon jsonb, active_from timestamptz default now(),
 active_to timestamptz, case_id uuid, created_by uuid, created_at timestamptz not null default now()
);

create table if not exists public.mdi_satellites (
 norad_id int primary key, name text not null, intl_designator text, operator text, country char(2), purpose text,
 is_imaging boolean default false, is_sar boolean default false, is_comms boolean default false, tle_line1 text, tle_line2 text,
 epoch timestamptz, inclination numeric(7,4), raan numeric(7,4), eccentricity numeric(9,8), argp numeric(7,4),
 mean_anomaly numeric(7,4), mean_motion numeric(11,8), bstar numeric(12,8), updated_at timestamptz not null default now()
);
create index if not exists mdi_sat_purpose on public.mdi_satellites(purpose) where purpose is not null;
create table if not exists public.mdi_satellite_passes (
 id bigserial primary key, norad_id int not null references public.mdi_satellites(norad_id) on delete cascade,
 observer_lat double precision not null, observer_lon double precision not null, observer_alt_m int not null default 0,
 aos timestamptz not null, los timestamptz not null, tca timestamptz not null, max_elevation numeric(6,3) not null,
 min_range_km numeric(10,3), start_azimuth numeric(6,2), end_azimuth numeric(6,2), sunlit boolean, computed_at timestamptz not null default now()
);
create index if not exists mdi_passes_norad_aos on public.mdi_satellite_passes(norad_id,aos);
create table if not exists public.mdi_satellite_observations (
 id uuid primary key default gen_random_uuid(), norad_id int references public.mdi_satellites(norad_id),
 observation_type text not null check(observation_type in('image','sar','ais','adsb','rf','gnss_interference','thermal','nightlights')),
 footprint_center_lat double precision, footprint_center_lon double precision, footprint_radius_km numeric(8,2), acquired_at timestamptz not null,
 asset_url text, asset_sha256 text, cloud_pct numeric(5,2), provider_id uuid references public.mdi_providers(id), case_id uuid,
 evidence_ref text, metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index if not exists mdi_satobs_time on public.mdi_satellite_observations(acquired_at desc);

create table if not exists public.mdi_graph_edges (
 id uuid primary key default gen_random_uuid(), src_id uuid not null references public.mdi_subjects(id) on delete cascade,
 dst_id uuid not null references public.mdi_subjects(id) on delete cascade, kind public.mdi_edge_kind not null,
 weight numeric(6,4) not null default 1.0 check(weight>=0 and weight<=1), confidence numeric(4,3) not null default 0.5,
 observations int not null default 1, first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
 case_ids uuid[] not null default '{}', evidence_refs text[] not null default '{}', attributes jsonb not null default '{}'::jsonb,
 unique(src_id,dst_id,kind)
);
create index if not exists mdi_edges_src on public.mdi_graph_edges(src_id,weight desc);
create index if not exists mdi_edges_dst on public.mdi_graph_edges(dst_id,weight desc);

create table if not exists public.mdi_correlations (
 id uuid primary key default gen_random_uuid(), correlation_type text not null, subject_ids uuid[] not null, edge_ids uuid[] not null default '{}',
 strength numeric(5,4) not null, p_value numeric(8,6), algorithm text not null, explanation jsonb not null default '{}'::jsonb,
 case_id uuid, created_at timestamptz not null default now()
);
create index if not exists mdi_corr_subjects on public.mdi_correlations using gin(subject_ids);
create table if not exists public.mdi_risk_assessments (
 id uuid primary key default gen_random_uuid(), subject_id uuid not null references public.mdi_subjects(id) on delete cascade,
 score numeric(5,2) not null, band public.mdi_risk_band not null, prior numeric(5,4) not null, log_odds numeric(10,4) not null,
 signals jsonb not null, model_version text not null default 'mdi-risk-v1', computed_at timestamptz not null default now()
);
create index if not exists mdi_risk_subj_time on public.mdi_risk_assessments(subject_id,computed_at desc);

create table if not exists public.mdi_provider_calls (
 id bigserial primary key, provider_id uuid references public.mdi_providers(id), capability public.mdi_capability not null,
 subject_id uuid references public.mdi_subjects(id) on delete set null, request_hash text not null, cache_hit boolean not null default false,
 ok boolean not null, http_status int, latency_ms int, cost_micros bigint not null default 0, error_code text, case_id uuid, actor_id uuid,
 called_at timestamptz not null default now()
);
create index if not exists mdi_pcalls_hash on public.mdi_provider_calls(request_hash,called_at desc);
create index if not exists mdi_pcalls_provider_time on public.mdi_provider_calls(provider_id,called_at desc);

create table if not exists public.mdi_case_links (
 id uuid primary key default gen_random_uuid(), case_id uuid not null, subject_id uuid references public.mdi_subjects(id) on delete cascade,
 edge_id uuid references public.mdi_graph_edges(id) on delete cascade, correlation_id uuid references public.mdi_correlations(id) on delete cascade,
 role text not null default 'related', added_by uuid, added_at timestamptz not null default now()
);
create index if not exists mdi_case_links_case on public.mdi_case_links(case_id);
commit;