begin;

create or replace function public.mdi_e164(p_raw text,p_default_cc text default null)
returns text language plpgsql immutable as $$
declare v text; v_cc text;
begin
 if p_raw is null then return null; end if;
 v:=regexp_replace(p_raw,'[^0-9+]','','g'); if v='' then return null; end if;
 if left(v,2)='00' then v:='+'||substr(v,3); end if;
 if left(v,1)<>'+' then
   v_cc:=coalesce(p_default_cc,''); if v_cc='' then return null; end if;
   v:='+'||regexp_replace(v_cc,'[^0-9]','','g')||regexp_replace(v,'^0+','','');
 end if;
 if length(regexp_replace(v,'[^0-9]','','g'))<7 then return null; end if;
 if length(v)>17 then return null; end if;
 return v;
end $$;

create or replace function public.mdi_luhn_ok(p_digits text)
returns boolean language plpgsql immutable as $$
declare d int;i int;sum int:=0;n int;alt boolean:=false;
begin
 n:=length(p_digits);if n=0 or p_digits !~ '^[0-9]+$' then return false;end if;
 for i in reverse n..1 loop
  d:=substr(p_digits,i,1)::int;
  if alt then d:=d*2;if d>9 then d:=d-9;end if;end if;
  sum:=sum+d;alt:=not alt;
 end loop;
 return sum%10=0;
end $$;

create or replace function public.mdi_imei_valid(p_imei text)
returns boolean language sql immutable as $$
 select length(regexp_replace(p_imei,'[^0-9]','','g'))=15
 and public.mdi_luhn_ok(regexp_replace(p_imei,'[^0-9]','','g'));
$$;

create or replace function public.mdi_imei_tac(p_imei text)
returns char(8) language sql immutable as $$
 select left(regexp_replace(p_imei,'[^0-9]','','g'),8)::char(8);
$$;

create or replace function public.mdi_decay(p_age_seconds numeric,p_half_life_seconds numeric)
returns numeric language sql immutable as $$
 select case when p_half_life_seconds is null or p_half_life_seconds<=0 then 1::numeric
 else power(0.5::numeric,greatest(p_age_seconds,0)/p_half_life_seconds) end;
$$;

create or replace function public.mdi_risk_from_signals(
 p_prior numeric,p_signals jsonb,
 out score numeric,out band public.mdi_risk_band,out log_odds numeric,out breakdown jsonb
) language plpgsql immutable as $$
declare s jsonb;lr numeric;w numeric;c numeric;a numeric;hl numeric;eff_lr numeric;lo numeric;pr numeric;
begin
 prior:=least(greatest(p_prior,0.000001),0.999999);lo:=ln(prior/(1-prior));breakdown:='[]'::jsonb;
 for s in select * from jsonb_array_elements(coalesce(p_signals,'[]'::jsonb)) loop
  lr:=coalesce((s->>'lr')::numeric,1);w:=coalesce((s->>'w')::numeric,1);c:=coalesce((s->>'conf')::numeric,1);
  a:=coalesce((s->>'age_s')::numeric,0);hl:=coalesce((s->>'half_life_s')::numeric,0);
  eff_lr:=1+(lr-1)*c*public.mdi_decay(a,hl);eff_lr:=greatest(eff_lr,0.0001);lo:=lo+w*ln(eff_lr);
  breakdown:=breakdown||jsonb_build_object('k',s->>'k','lr',lr,'eff_lr',round(eff_lr,4),'contrib',round(w*ln(eff_lr),4));
 end loop;
 pr:=1.0/(1.0+exp(-lo));score:=round((pr*100)::numeric,2);log_odds:=round(lo,4);
 band:=case when pr>=.90 then 'critical'::public.mdi_risk_band when pr>=.70 then 'high'::public.mdi_risk_band
 when pr>=.40 then 'medium'::public.mdi_risk_band when pr>=.10 then 'low'::public.mdi_risk_band else 'unknown'::public.mdi_risk_band end;
end $$;

create or replace function public.mdi_upsert_subject(
 p_kind public.mdi_subject_kind,p_canonical text,p_display text default null,p_country char(2) default null,
 p_attrs jsonb default '{}'::jsonb,p_pii smallint default 0
) returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 insert into public.mdi_subjects(kind,canonical,display,country_iso2,attributes,pii_grade,last_seen)
 values(p_kind,p_canonical,p_display,p_country,p_attrs,p_pii,now())
 on conflict(kind,canonical) do update set last_seen=now(),display=coalesce(excluded.display,public.mdi_subjects.display),
 attributes=public.mdi_subjects.attributes||excluded.attributes returning id into v_id;
 return v_id;
end $$;

create or replace function public.mdi_link(
 p_src uuid,p_dst uuid,p_kind public.mdi_edge_kind,p_weight numeric default 1.0,p_conf numeric default .5,
 p_case uuid default null,p_evidence text default null,p_attrs jsonb default '{}'::jsonb
) returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 insert into public.mdi_graph_edges(src_id,dst_id,kind,weight,confidence,observations,case_ids,evidence_refs,attributes)
 values(p_src,p_dst,p_kind,p_weight,p_conf,1,
  case when p_case is null then '{}' else array[p_case] end,
  case when p_evidence is null then '{}' else array[p_evidence] end,p_attrs)
 on conflict(src_id,dst_id,kind) do update set
  weight=round((public.mdi_graph_edges.weight*.75+excluded.weight*.25)::numeric,4),
  confidence=greatest(public.mdi_graph_edges.confidence,excluded.confidence),
  observations=public.mdi_graph_edges.observations+1,last_seen=now(),
  case_ids=(select array(select distinct unnest(public.mdi_graph_edges.case_ids||excluded.case_ids))),
  evidence_refs=(select array(select distinct unnest(public.mdi_graph_edges.evidence_refs||excluded.evidence_refs))),
  attributes=public.mdi_graph_edges.attributes||excluded.attributes
 returning id into v_id;
 return v_id;
end $$;

create or replace function public.mdi_shortest_path(
 p_from uuid,p_to uuid,p_max_depth int default 4,p_min_weight numeric default .05
) returns table(depth int,path uuid[],kinds text[],total_cost numeric) language sql stable as $$
with recursive walk as(
 select 1 depth,array[p_from] path,array[]::text[] kinds,0::numeric cost,p_from node,false cycle
 union all
 select w.depth+1,w.path||e.dst_id,w.kinds||e.kind::text,
 w.cost+(1.0/greatest(e.weight*e.confidence,.001)),e.dst_id,e.dst_id=any(w.path)
 from walk w join public.mdi_graph_edges e on e.src_id=w.node
 where w.depth<p_max_depth and not w.cycle and e.weight>=p_min_weight
)
select depth,path,kinds,round(cost,4) from walk where node=p_to and not cycle order by cost asc limit 10;
$$;

create or replace function public.mdi_neighborhood(
 p_subject uuid,p_hops int default 2,p_min_weight numeric default .05
) returns table(subject_id uuid,kind public.mdi_subject_kind,canonical text,hops int,via text[],path_weight numeric,risk numeric)
language sql stable as $$
with recursive n as(
 select p_subject id,0 hops,array[]::text[] via,1.0::numeric pw
 union all
 select e.dst_id,n.hops+1,n.via||e.kind::text,n.pw*e.weight*e.confidence
 from n join public.mdi_graph_edges e on e.src_id=n.id
 where n.hops<p_hops and e.weight>=p_min_weight and e.dst_id<>p_subject
)
select distinct on(n.id)s.id,s.kind,s.canonical,n.hops,n.via,round(n.pw,4),s.risk_score
from n join public.mdi_subjects s on s.id=n.id where n.hops>0 order by n.id,n.pw desc;
$$;

create or replace function public.mdi_haversine_m(lat1 double precision,lon1 double precision,lat2 double precision,lon2 double precision)
returns double precision language sql immutable as $$
 select 6371008.8*2*asin(sqrt(power(sin(radians(lat2-lat1)/2),2)+cos(radians(lat1))*cos(radians(lat2))*power(sin(radians(lon2-lon1)/2),2)));
$$;

create or replace function public.mdi_point_in_ring(ring jsonb,p_lat double precision,p_lon double precision)
returns boolean language plpgsql immutable as $$
declare i int;j int;n int;xi double precision;yi double precision;xj double precision;yj double precision;inside boolean:=false;
begin
 n:=jsonb_array_length(ring);if n<3 then return false;end if;j:=n-1;
 for i in 0..n-1 loop
  xi:=(ring->i->>0)::double precision;yi:=(ring->i->>1)::double precision;xj:=(ring->j->>0)::double precision;yj:=(ring->j->>1)::double precision;
  if((yi>p_lat)<>(yj>p_lat)) and(p_lon<(xj-xi)*(p_lat-yi)/nullif(yj-yi,0)+xi)then inside:=not inside;end if;j:=i;
 end loop;return inside;
end $$;

create or replace function public.mdi_geofence_hit(p_fence uuid,p_lat double precision,p_lon double precision)
returns boolean language plpgsql stable as $$
declare f public.mdi_geofences;
begin
 select * into f from public.mdi_geofences where id=p_fence;if not found then return false;end if;
 if f.kind='circle' then return public.mdi_haversine_m(f.center_lat,f.center_lon,p_lat,p_lon)<=f.radius_m;end if;
 return public.mdi_point_in_ring(f.polygon->'coordinates'->0,p_lat,p_lon);
end $$;

create or replace function public.mdi_refresh_risk(p_subject uuid)
returns public.mdi_risk_assessments language plpgsql security definer set search_path=public as $$
declare
 v_subject public.mdi_subjects;v_signals jsonb:='[]'::jsonb;v_prior numeric:=.02;v_rec public.mdi_risk_assessments;v_now timestamptz:=now();e record;r record;
begin
 select * into v_subject from public.mdi_subjects where id=p_subject;
 if not found then raise exception 'subject % not found',p_subject;end if;
 for e in select occurred_at from public.mdi_carrier_events where subject_id=p_subject and event_type in('sim_swap','port_out','esim_download') order by occurred_at desc limit 5 loop
  v_signals:=v_signals||jsonb_build_object('k','sim_swap','lr',22.0,'w',1.0,'conf',.9,'age_s',extract(epoch from(v_now-e.occurred_at)),'half_life_s',604800);
 end loop;
 for r in select count(*) c,avg(severity) s,max(occurred_at)m from public.mdi_caller_reports where subject_id=p_subject and occurred_at>v_now-interval '180 days' loop
  if r.c>0 then v_signals:=v_signals||jsonb_build_object('k','caller_reports','lr',1+ln(1+r.c)*coalesce(r.s,1)*.6,'w',1.0,'conf',least(.5+r.c*.05,.95),'age_s',extract(epoch from(v_now-r.m)),'half_life_s',2592000);end if;
 end loop;
 if exists(select 1 from public.mdi_number_intel where subject_id=p_subject and line_type='voip') then
  v_signals:=v_signals||jsonb_build_object('k','voip_line','lr',3.5,'w',.8,'conf',.85,'age_s',0,'half_life_s',0);
 end if;
 if v_subject.kind='msisdn' then
  declare v_imeis int;begin
   select count(distinct dst_id) into v_imeis from public.mdi_graph_edges where src_id=p_subject and kind in('registered_on','shared_imei');
   if v_imeis>=5 then v_signals:=v_signals||jsonb_build_object('k','multi_imei','lr',1+v_imeis*1.4,'w',.9,'conf',least(.4+v_imeis*.08,.95),'age_s',0,'half_life_s',0);end if;
  end;
 end if;
 declare v_bad numeric;begin
  select coalesce(sum(e.weight*e.confidence*case s.risk_band when 'critical' then 1.0 when 'high' then .7 when 'medium' then .35 else .05 end),0)
  into v_bad from public.mdi_graph_edges e join public.mdi_subjects s on s.id=e.dst_id where e.src_id=p_subject and s.risk_score>40;
  if v_bad>.2 then v_signals:=v_signals||jsonb_build_object('k','graph_proximity_bad','lr',1+v_bad*4,'w',.85,'conf',.75,'age_s',0,'half_life_s',0);end if;
 end;
 if exists(select 1 from public.mdi_satellite_observations o join public.mdi_case_links cl on cl.case_id=o.case_id where cl.subject_id=p_subject and o.acquired_at>v_now-interval '24 hours') then
  v_signals:=v_signals||jsonb_build_object('k','satellite_overflight_24h','lr',2.2,'w',.6,'conf',.6,'age_s',0,'half_life_s',0);
 end if;
 insert into public.mdi_risk_assessments(subject_id,score,band,prior,log_odds,signals)
 select p_subject,x.score,x.band,v_prior,x.log_odds,v_signals from public.mdi_risk_from_signals(v_prior,v_signals)x returning * into v_rec;
 update public.mdi_subjects set risk_score=v_rec.score,risk_band=v_rec.band,confidence=least(.99,.4+jsonb_array_length(v_signals)*.1),last_seen=now() where id=p_subject;
 return v_rec;
end $$;

commit;