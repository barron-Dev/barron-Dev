begin;

drop function if exists public.mdi_emit_advanced_alert(text,uuid,mdi_risk_band,numeric,text,text,jsonb,uuid);
create or replace function public.mdi_emit_advanced_alert(
  p_alert_type text,p_subject_id uuid,p_severity public.mdi_risk_band,p_score numeric,
  p_action text,p_algorithm text,p_explanation jsonb,p_case_id uuid,p_tenant_id uuid
) returns uuid
language plpgsql security invoker set search_path=''
as $$
declare v_id uuid;
begin
  if p_tenant_id is null then raise exception 'mdi_alert_tenant_required'; end if;
  if p_subject_id is not null and not exists(
    select 1 from public.mdi_subject_tenants st
    where st.subject_id=p_subject_id and st.tenant_id=p_tenant_id
  ) then raise exception 'mdi_alert_subject_tenant_mismatch'; end if;
  if p_case_id is not null and not exists(
    select 1 from public.crime_cases c
    where c.id=p_case_id and c.tenant_id=p_tenant_id
  ) then raise exception 'mdi_alert_case_tenant_mismatch'; end if;
  insert into public.mdi_advanced_alerts(
    alert_type,subject_id,severity,score,action,algorithm,explanation,case_id,tenant_id
  ) values(
    p_alert_type,p_subject_id,p_severity,p_score,p_action,p_algorithm,
    coalesce(p_explanation,'{}'::jsonb),p_case_id,p_tenant_id
  ) returning id into v_id;
  perform pg_notify(
    'mdi.advanced.alert',
    json_build_object(
      'id',v_id,'alert_type',p_alert_type,'subject_id',p_subject_id,
      'tenant_id',p_tenant_id,'created_at',now()
    )::text
  );
  return v_id;
end $$;

revoke execute on function public.mdi_emit_advanced_alert(text,uuid,mdi_risk_band,numeric,text,text,jsonb,uuid,uuid)
from public,anon,authenticated;
grant execute on function public.mdi_emit_advanced_alert(text,uuid,mdi_risk_band,numeric,text,text,jsonb,uuid,uuid)
to service_role;

create or replace function public.mdi_simswap_guard()
returns trigger language plpgsql security invoker set search_path=''
as $$
declare h numeric; v_tenant_id uuid;
begin
  h:=public.mdi_simswap_hazard(new.subject_id);
  select st.tenant_id into v_tenant_id
  from public.mdi_subject_tenants st
  where st.subject_id=new.subject_id
    and 1=(select count(*) from public.mdi_subject_tenants x where x.subject_id=new.subject_id);
  if h>.65 and v_tenant_id is not null then
    perform public.mdi_emit_advanced_alert(
      'simswap_preemptive',new.subject_id,
      case when h>=.9 then 'critical'::public.mdi_risk_band
           when h>=.75 then 'high'::public.mdi_risk_band
           else 'medium'::public.mdi_risk_band end,
      h,'freeze_otp_route','cox_style_hazard_v1',
      jsonb_build_object('hazard',h,'event_type',new.event_type,'occurred_at',new.occurred_at),
      null,v_tenant_id
    );
  end if;
  return new;
end $$;

create or replace function public.mdi_recycle_quarantine()
returns trigger language plpgsql security invoker set search_path=''
as $$
declare prior numeric; v_tenant_id uuid;
begin
  if new.event_type='msisdn_recycle' then
    select risk_score into prior from public.mdi_subjects where id=new.subject_id for update;
    update public.mdi_subjects
    set attributes=attributes||jsonb_build_object(
      'quarantined_until',(now()+interval '45 days')::text,
      'prior_owner_risk',coalesce(prior,0)
    ),risk_score=0,risk_band='unknown'
    where id=new.subject_id;
    select st.tenant_id into v_tenant_id
    from public.mdi_subject_tenants st
    where st.subject_id=new.subject_id
      and 1=(select count(*) from public.mdi_subject_tenants x where x.subject_id=new.subject_id);
    if v_tenant_id is not null then
      perform public.mdi_emit_advanced_alert(
        'msisdn_recycle_quarantine',new.subject_id,'high',
        least(1,coalesce(prior,0)/100),
        'quarantine_otp_and_mobile_money','number_recycling_window_v1',
        jsonb_build_object(
          'quarantined_until',(now()+interval '45 days')::text,
          'prior_owner_risk',coalesce(prior,0)
        ),null,v_tenant_id
      );
    end if;
  end if;
  return new;
end $$;

create or replace function public.mdi_silent_sms_alert()
returns trigger language plpgsql security invoker set search_path=''
as $$
declare cnt int; sources jsonb; v_tenant_id uuid;
begin
  if (new.raw->>'msg_class')='0' and new.channel='sms' and new.b_subject_id is not null then
    select count(*),coalesce(json_agg(distinct a_subject_id),'[]'::json)
    into cnt,sources
    from public.mdi_comms_events
    where b_subject_id=new.b_subject_id
      and (raw->>'msg_class')='0'
      and started_at>now()-interval '15 min';
    select st.tenant_id into v_tenant_id
    from public.mdi_subject_tenants st
    where st.subject_id=new.b_subject_id
      and 1=(select count(*) from public.mdi_subject_tenants x where x.subject_id=new.b_subject_id);
    if cnt>3 and v_tenant_id is not null then
      perform public.mdi_emit_advanced_alert(
        'ss7_silent_tracking',new.b_subject_id,'high',
        least(1,cnt/10.0),'investigate_silent_sms_source','silent_sms_burst_v1',
        jsonb_build_object('count',cnt,'source_ids',sources),null,v_tenant_id
      );
    end if;
  end if;
  return new;
end $$;

create or replace function public.mdi_materialize_wangiri()
returns integer language plpgsql security invoker set search_path=''
as $$
declare r record; v_tenant_id uuid; v_count integer:=0;
begin
  for r in select * from public.mdi_wangiri_bursts loop
    select st.tenant_id into v_tenant_id
    from public.mdi_subject_tenants st
    where st.subject_id=r.b_subject_id
      and 1=(select count(*) from public.mdi_subject_tenants x where x.subject_id=r.b_subject_id);
    if v_tenant_id is not null then
      perform public.mdi_emit_advanced_alert(
        'wangiri_burst',r.b_subject_id,
        case when r.ring_short>50 then 'critical'::public.mdi_risk_band
             else 'high'::public.mdi_risk_band end,
        least(1,r.ring_short/100.0),'investigate_wangiri','wangiri_burst_v1',
        to_jsonb(r),null,v_tenant_id
      );
      v_count:=v_count+1;
    end if;
  end loop;
  return v_count;
end $$;

create or replace function public.mdi_materialize_grey_routes()
returns integer language plpgsql security invoker set search_path=''
as $$
declare r record; v_count integer:=0;
begin
  for r in
    with single_subject_tenants as (
      select subject_id from public.mdi_subject_tenants
      group by subject_id having count(*)=1
    )
    select
      c.msg_hash,st.tenant_id,
      count(distinct c.raw->>'smsc') smsc_count,
      count(distinct c.raw->>'orig_mcc_mnc') origin_count,
      count(distinct c.a_subject_id) sender_count,
      jsonb_agg(distinct c.a_subject_id) sender_ids
    from public.mdi_comms_events c
    join single_subject_tenants ss on ss.subject_id=c.a_subject_id
    join public.mdi_subject_tenants st on st.subject_id=ss.subject_id
    where c.channel='sms'
      and c.started_at>now()-interval '24 hours'
      and c.msg_hash is not null
    group by c.msg_hash,st.tenant_id
    having count(distinct c.raw->>'smsc')>2
       and count(distinct c.raw->>'orig_mcc_mnc')>1
  loop
    perform public.mdi_emit_advanced_alert(
      'grey_route_a2p',null,'high'::public.mdi_risk_band,
      least(1,r.smsc_count/10.0),'investigate_grey_route_a2p','grey_route_a2p_v1',
      jsonb_build_object(
        'msg_hash',r.msg_hash,'smsc_count',r.smsc_count,
        'origin_count',r.origin_count,'sender_count',r.sender_count,
        'sender_ids',r.sender_ids
      ),null,r.tenant_id
    );
    v_count:=v_count+1;
  end loop;
  return v_count;
end $$;

alter table public.mdi_advanced_alerts
  alter column tenant_id set not null;

alter table public.mdi_observer_consent
  add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
create index if not exists mdi_observer_consent_tenant_observer_idx
  on public.mdi_observer_consent(tenant_id,observer_id);

alter table public.mdi_rf_observations
  add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
create index if not exists mdi_rf_observations_tenant_observed_idx
  on public.mdi_rf_observations(tenant_id,observed_at desc);

alter table public.mdi_rf_threats
  add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
create index if not exists mdi_rf_threats_tenant_created_idx
  on public.mdi_rf_threats(tenant_id,created_at desc);

commit;