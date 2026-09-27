begin;

create table if not exists public.mdi_advanced_alerts (
  id uuid primary key default gen_random_uuid(),
  alert_type text not null,
  subject_id uuid references public.mdi_subjects(id) on delete set null,
  severity public.mdi_risk_band not null default 'medium',
  score numeric(6,4),
  action text,
  algorithm text not null,
  explanation jsonb not null default '{}',
  case_id uuid,
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index if not exists mdi_adv_alerts_time_idx on public.mdi_advanced_alerts(created_at desc);
create index if not exists mdi_adv_alerts_subject_idx on public.mdi_advanced_alerts(subject_id, created_at desc);
create index if not exists mdi_adv_alerts_type_idx on public.mdi_advanced_alerts(alert_type, created_at desc);

create table if not exists public.mdi_federation_peers (
  peer_id text primary key,
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.mdi_federated_outbox (
  id uuid primary key default gen_random_uuid(),
  peer_id text not null references public.mdi_federation_peers(peer_id) on delete cascade,
  canonical_hash text not null,
  risk_score numeric(5,2) not null,
  risk_band public.mdi_risk_band not null,
  observed_at timestamptz not null,
  published_at timestamptz,
  created_at timestamptz not null default now(),
  unique(peer_id, canonical_hash)
);
create index if not exists mdi_fed_outbox_pending_idx
  on public.mdi_federated_outbox(peer_id, created_at)
  where published_at is null;

alter table public.mdi_advanced_alerts enable row level security;
alter table public.mdi_federation_peers enable row level security;
alter table public.mdi_federated_outbox enable row level security;

drop policy if exists mdi_advanced_alerts_service_role on public.mdi_advanced_alerts;
create policy mdi_advanced_alerts_service_role on public.mdi_advanced_alerts
  for all to service_role using (true) with check (true);
drop policy if exists mdi_federation_peers_service_role on public.mdi_federation_peers;
create policy mdi_federation_peers_service_role on public.mdi_federation_peers
  for all to service_role using (true) with check (true);
drop policy if exists mdi_federated_outbox_service_role on public.mdi_federated_outbox;
create policy mdi_federated_outbox_service_role on public.mdi_federated_outbox
  for all to service_role using (true) with check (true);

create or replace function public.mdi_emit_advanced_alert(
  p_alert_type text,
  p_subject_id uuid,
  p_severity public.mdi_risk_band,
  p_score numeric,
  p_action text,
  p_algorithm text,
  p_explanation jsonb,
  p_case_id uuid default null
) returns uuid
language plpgsql
security invoker
set search_path = public
as $$
declare v_id uuid;
begin
  insert into public.mdi_advanced_alerts(
    alert_type, subject_id, severity, score, action, algorithm, explanation, case_id
  ) values (
    p_alert_type, p_subject_id, p_severity, p_score, p_action, p_algorithm,
    coalesce(p_explanation,'{}'::jsonb), p_case_id
  ) returning id into v_id;

  perform pg_notify(
    'mdi.advanced.alert',
    json_build_object(
      'id', v_id,
      'alert_type', p_alert_type,
      'subject_id', p_subject_id,
      'severity', p_severity,
      'score', p_score,
      'action', p_action
    )::text
  );
  return v_id;
end
$$;

create or replace function public.mdi_simswap_hazard(p_subject uuid)
returns numeric
language sql
stable
set search_path = public
as $$
with sig as (
  select
    (select count(*) from public.mdi_carrier_events
      where subject_id=p_subject and event_type='roaming_on'
        and occurred_at > now()-interval '7 days') as roam_flips,
    (select count(*) from public.mdi_provider_calls
      where subject_id=p_subject and capability='carrier_lookup'
        and called_at > now()-interval '1 hour') as hlr_pings,
    (select count(distinct to_imei) from public.mdi_carrier_events
      where subject_id=p_subject and to_imei is not null
        and occurred_at > now()-interval '48 hours') as imei_churn,
    (select count(*) from public.mdi_carrier_events
      where subject_id=p_subject
        and extract(hour from occurred_at) between 1 and 5
        and occurred_at > now()-interval '3 days') as night_touch
)
select least(1.0, 1 - exp(-(
  0.9*ln(1+roam_flips) +
  0.7*ln(1+hlr_pings) +
  1.4*ln(1+imei_churn) +
  0.5*night_touch
)))::numeric
from sig
$$;

create or replace function public.mdi_simswap_guard()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare h numeric;
begin
  h := public.mdi_simswap_hazard(new.subject_id);
  if h > 0.65 then
    perform public.mdi_emit_advanced_alert(
      'simswap_preemptive',
      new.subject_id,
      case when h >= .9 then 'critical'::public.mdi_risk_band
           when h >= .75 then 'high'::public.mdi_risk_band
           else 'medium'::public.mdi_risk_band end,
      h,
      'freeze_otp_route',
      'cox_style_hazard_v1',
      jsonb_build_object('hazard',h,'event_type',new.event_type,'occurred_at',new.occurred_at)
    );
  end if;
  return new;
end
$$;

drop trigger if exists t_simswap_guard on public.mdi_carrier_events;
create trigger t_simswap_guard
after insert on public.mdi_carrier_events
for each row when (new.event_type in ('sim_activate','esim_download','roaming_on','imei_change'))
execute function public.mdi_simswap_guard();

create or replace view public.mdi_wangiri_bursts as
with recent as (
  select
    e.b_subject_id,
    e.a_subject_id,
    e.duration_s,
    e.started_at
  from public.mdi_comms_events e
  where e.channel='voice'
    and e.started_at > now()-interval '2 hours'
    and e.b_subject_id is not null
),
grouped as (
  select
    b_subject_id,
    count(*) filter (where coalesce(duration_s,0) < 3) as ring_short,
    count(*) filter (where coalesce(duration_s,0) = 0) as miss_calls,
    count(distinct a_subject_id) as unique_callers,
    max(started_at)-min(started_at) as window,
    count(*) as total_calls
  from recent
  group by b_subject_id
)
select
  g.*,
  case when g.unique_callers > 0
       then greatest(0, least(1, ln(1+g.unique_callers)/ln(1+g.total_calls)))
       else 0 end as caller_diversity
from grouped g
where g.ring_short > 20;

create or replace function public.mdi_irsf_score(p_cell_id text)
returns numeric
language sql
stable
set search_path = public
as $$
select least(1.0, ln(1 + count(distinct c.a_subject_id)) / 8.0)
from public.mdi_comms_events c
join public.mdi_location_signals l
  on l.subject_id = c.a_subject_id
 and l.cid = p_cell_id
 and abs(extract(epoch from (l.observed_at - c.started_at))) < 30
where c.started_at > now() - interval '10 min'
  and c.channel='voice'
  and coalesce(c.duration_s,0) between 1 and 30
$$;

create or replace function public.mdi_recycle_quarantine()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare prior numeric;
begin
  if new.event_type = 'msisdn_recycle' then
    select risk_score into prior from public.mdi_subjects where id=new.subject_id for update;
    update public.mdi_subjects
      set attributes = attributes || jsonb_build_object(
        'quarantined_until',(now()+interval '45 days')::text,
        'prior_owner_risk',coalesce(prior,0)
      ),
      risk_score = 0,
      risk_band = 'unknown'
    where id = new.subject_id;

    perform public.mdi_emit_advanced_alert(
      'msisdn_recycle_quarantine',
      new.subject_id,
      'high',
      least(1,coalesce(prior,0)/100),
      'quarantine_otp_and_mobile_money',
      'number_recycling_window_v1',
      jsonb_build_object('quarantined_until',(now()+interval '45 days'),'prior_owner_risk',coalesce(prior,0))
    );
  end if;
  return new;
end
$$;

drop trigger if exists t_recycle_quarantine on public.mdi_carrier_events;
create trigger t_recycle_quarantine
after insert on public.mdi_carrier_events
for each row when (new.event_type='msisdn_recycle')
execute function public.mdi_recycle_quarantine();

create or replace view public.mdi_grey_routes as
select
  msg_hash,
  count(distinct (raw->>'smsc')) as smsc_count,
  count(distinct (raw->>'orig_mcc_mnc')) as origin_count,
  count(distinct a_subject_id) as senders,
  array_agg(distinct raw->>'sender_id') filter (where raw->>'sender_id' is not null) as claimed_ids
from public.mdi_comms_events
where channel='sms'
  and started_at > now()-interval '24 hours'
  and msg_hash is not null
group by msg_hash
having count(distinct (raw->>'smsc')) > 2
   and count(distinct (raw->>'orig_mcc_mnc')) > 1;

create or replace function public.mdi_silent_sms_alert()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare cnt int;
declare sources jsonb;
begin
  if (new.raw->>'msg_class')='0' and new.channel='sms' and new.b_subject_id is not null then
    select count(*), coalesce(json_agg(distinct a_subject_id),'[]'::json)
      into cnt, sources
      from public.mdi_comms_events
      where b_subject_id=new.b_subject_id
        and (raw->>'msg_class')='0'
        and started_at > now()-interval '15 min';

    if cnt > 3 then
      perform public.mdi_emit_advanced_alert(
        'ss7_silent_tracking',
        new.b_subject_id,
        'high',
        least(1, cnt/10.0),
        'investigate_silent_sms_source',
        'silent_sms_burst_v1',
        jsonb_build_object('count',cnt,'source_ids',sources)
      );
    end if;
  end if;
  return new;
end
$$;

drop trigger if exists t_silent_sms on public.mdi_comms_events;
create trigger t_silent_sms
after insert on public.mdi_comms_events
for each row execute function public.mdi_silent_sms_alert();

create or replace function public.mdi_materialize_wangiri()
returns integer
language plpgsql
security invoker
set search_path = public
as $$
declare n integer := 0;
declare r record;
begin
  for r in select * from public.mdi_wangiri_bursts loop
    perform public.mdi_emit_advanced_alert(
      'wangiri_burst',
      r.b_subject_id,
      case when r.unique_callers >= 100 then 'critical'::public.mdi_risk_band
           when r.unique_callers >= 50 then 'high'::public.mdi_risk_band
           else 'medium'::public.mdi_risk_band end,
      least(1, r.unique_callers/100.0),
      'block_or_review_callback_route',
      'wangiri_burst_v1',
      jsonb_build_object(
        'ring_short',r.ring_short,
        'miss_calls',r.miss_calls,
        'unique_callers',r.unique_callers,
        'window',r.window,
        'caller_diversity',r.caller_diversity
      )
    );
    n := n + 1;
  end loop;
  return n;
end
$$;

create or replace function public.mdi_materialize_grey_routes()
returns integer
language plpgsql
security invoker
set search_path = public
as $$
declare n integer := 0;
declare r record;
begin
  for r in select * from public.mdi_grey_routes loop
    perform public.mdi_emit_advanced_alert(
      'grey_route_a2p',
      null,
      'high',
      least(1, greatest(r.smsc_count,r.origin_count)/5.0),
      'route_to_sms_gateway_review',
      'grey_route_smsc_fingerprint_v1',
      jsonb_build_object(
        'msg_hash',r.msg_hash,
        'smsc_count',r.smsc_count,
        'origin_count',r.origin_count,
        'senders',r.senders,
        'claimed_ids',r.claimed_ids
      )
    );
    n := n + 1;
  end loop;
  return n;
end
$$;

create or replace function public.mdi_federated_publish(p_peer text)
returns integer
language plpgsql
security invoker
set search_path = public
as $$
declare n integer := 0;
declare secret text;
begin
  if not exists(select 1 from public.mdi_federation_peers where peer_id=p_peer and enabled) then
    raise exception 'mdi federation peer is not allowlisted';
  end if;
  secret := current_setting('mdi.federation_pepper', true);
  if secret is null or secret='' then
    raise exception 'mdi federation pepper is not configured';
  end if;

  insert into public.mdi_federated_outbox(peer_id,canonical_hash,risk_score,risk_band,observed_at)
  select
    p_peer,
    encode(hmac(s.canonical,secret,'sha256'),'hex'),
    s.risk_score,
    s.risk_band,
    s.last_seen
  from public.mdi_subjects s
  where s.risk_band in ('high','critical')
    and s.last_seen > now()-interval '7 days'
  on conflict(peer_id,canonical_hash) do nothing;

  get diagnostics n = row_count;
  return n;
end
$$;

revoke all on function public.mdi_federated_publish(text) from public;
grant execute on function public.mdi_federated_publish(text) to service_role;

alter table public.mdi_advanced_alerts add column if not exists dedupe_key text;
create unique index if not exists mdi_adv_alerts_dedupe_idx on public.mdi_advanced_alerts(dedupe_key) where dedupe_key is not null;

revoke all on public.mdi_wangiri_bursts from anon, authenticated;
revoke all on public.mdi_grey_routes from anon, authenticated;
grant select on public.mdi_wangiri_bursts, public.mdi_grey_routes to service_role;

revoke all on function public.mdi_simswap_hazard(uuid) from public;
revoke all on function public.mdi_simswap_guard() from public;
revoke all on function public.mdi_irsf_score(text) from public;
revoke all on function public.mdi_recycle_quarantine() from public;
revoke all on function public.mdi_silent_sms_alert() from public;
revoke all on function public.mdi_materialize_wangiri() from public;
revoke all on function public.mdi_materialize_grey_routes() from public;
grant execute on function public.mdi_materialize_wangiri() to service_role;
grant execute on function public.mdi_materialize_grey_routes() to service_role;

commit;
