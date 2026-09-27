begin;

insert into public.mdi_providers
  (slug,name,kind,capabilities,coverage,base_url,secret_ref,cost_micros,weight,status)
values
 ('camara','GSMA Open Gateway','camara',
  '{number_verify,sim_swap,device_reachability,device_identity,location_verify,location_retrieve,roaming,kyc_match}',
  '{"countries":["AE","SA","QA","KW","BH","OM","JO","EG"],"auth":"2lo"}',
  null,'CAMARA_CLIENT_SECRET',12000,1.0,'disabled'),
 ('twilio_lookup','Twilio Lookup v2','aggregator',
  '{carrier_lookup,line_type,sim_swap,number_reputation,kyc_match}',
  '{"countries":["*"],"latency_class":"fast"}',
  'https://lookups.twilio.com','TWILIO_AUTH_TOKEN',8000,0.9,'disabled'),
 ('numverify','Numverify','osint',
  '{carrier_lookup,line_type}',
  '{"countries":["*"],"latency_class":"medium"}',
  'https://apilayer.net/api','NUMVERIFY_KEY',500,0.6,'disabled'),
 ('celestrak','CelesTrak GP','satellite',
  '{tle_catalog}',
  '{"countries":["*"],"latency_class":"batch"}',
  'https://celestrak.org','',0,1.0,'active'),
 ('sentinel_hub','Sentinel Hub / Copernicus','satellite',
  '{imagery}',
  '{"countries":["*"],"latency_class":"batch"}',
  'https://services.sentinel-hub.com','SENTINEL_HUB_CLIENT_SECRET',25000,0.85,'disabled'),
 ('internal_graph','Cyclothone Internal Graph','internal',
  '{number_reputation}',
  '{"countries":["*"],"latency_class":"instant"}',
  null,null,0,1.0,'active')
on conflict (slug) do update set
  capabilities=excluded.capabilities,
  coverage=excluded.coverage,
  base_url=excluded.base_url,
  secret_ref=excluded.secret_ref,
  cost_micros=excluded.cost_micros,
  weight=excluded.weight,
  status=case when public.mdi_providers.status='active' and excluded.status='disabled' then public.mdi_providers.status else excluded.status end,
  updated_at=now();

insert into public.mdi_operators
 (mcc,mnc,name,country_iso2,brand,is_mno,camara_ready)
values
 ('424','02','Etisalat','AE','e&',true,true),
 ('424','03','du','AE','du',true,true),
 ('420','01','STC','SA','stc',true,false),
 ('420','03','Mobily','SA','Mobily',true,false),
 ('420','04','Zain KSA','SA','Zain',true,false),
 ('427','01','Ooredoo','QA','Ooredoo',true,false),
 ('427','02','Vodafone','QA','Vodafone',true,false),
 ('419','02','Zain KW','KW','Zain',true,false),
 ('419','03','Ooredoo','KW','Ooredoo',true,false),
 ('419','04','STC KW','KW','stc',true,false)
on conflict (mcc,mnc) do nothing;

commit;
