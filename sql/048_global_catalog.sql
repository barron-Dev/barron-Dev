-- sql/048_global_catalog.sql
-- Global tenant-selectable catalogs. No tenant is subscribed automatically.

create table if not exists lens_channel_catalog (
    id text primary key,
    platform text not null check (platform in ('telegram','discord','irc')),
    handle text not null,
    language text,
    countries text[] not null default '{}',
    categories text[] not null default '{}',
    verified boolean not null default false
);

create table if not exists lens_channel_subscriptions (
    tenant_id uuid not null references tenants(id) on delete cascade,
    channel_id text not null references lens_channel_catalog(id) on delete cascade,
    enabled boolean not null default true,
    subscribed_at timestamptz not null default now(),
    primary key (tenant_id, channel_id)
);
alter table lens_channel_subscriptions enable row level security;
drop policy if exists lens_channel_subs_tenant on lens_channel_subscriptions;
create policy lens_channel_subs_tenant on lens_channel_subscriptions
    for all to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
    with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists tenant_preferences (
    tenant_id uuid primary key references tenants(id) on delete cascade,
    default_locale text not null default 'en' check (default_locale ~ '^[a-z]{2}(-[A-Z]{2})?$'),
    default_region text not null default 'US' check (default_region ~ '^[A-Z]{2}$'),
    timezone text not null default 'UTC',
    country text not null default 'US' check (country ~ '^[A-Z]{2}$'),
    alert_languages text[] not null default array['en'],
    updated_at timestamptz not null default now()
);
alter table tenant_preferences enable row level security;
drop policy if exists tenant_prefs_tenant on tenant_preferences;
create policy tenant_prefs_tenant on tenant_preferences
    for all to authenticated
    using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
    with check (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create or replace function bootstrap_tenant_preferences()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into tenant_preferences (tenant_id) values (new.id)
    on conflict (tenant_id) do nothing;
    return new;
end;
$$;
revoke all on function bootstrap_tenant_preferences() from public, anon, authenticated;
grant execute on function bootstrap_tenant_preferences() to service_role;

drop trigger if exists tenant_prefs_bootstrap on tenants;
create trigger tenant_prefs_bootstrap
    after insert on tenants
    for each row execute function bootstrap_tenant_preferences();

-- GSMA operator catalog. Credentials/endpoints are intentionally not populated
-- here; operator onboarding must supply verified integration metadata.
insert into gsma_operators (id,name,country,mcc_mnc,oidc_issuer,oidc_client_id,oidc_secret_ref)
values
('mtn-ng','MTN Nigeria','NG','621-30',null,null,null),
('airtel-ng','Airtel Nigeria','NG','621-20',null,null,null),
('glo-ng','Glo Nigeria','NG','621-50',null,null,null),
('safaricom-ke','Safaricom','KE','639-02',null,null,null),
('airtel-ke','Airtel Kenya','KE','639-03',null,null,null),
('mtn-za','MTN South Africa','ZA','655-10',null,null,null),
('vodacom-za','Vodacom','ZA','655-01',null,null,null),
('mtn-gh','MTN Ghana','GH','620-01',null,null,null),
('mtn-bj','MTN Benin','BJ','616-01',null,null,null),
('orange-ci','Orange Côte d’Ivoire','CI','612-02',null,null,null),
('mtn-cm','MTN Cameroon','CM','624-01',null,null,null),
('orange-sn','Orange Senegal','SN','608-01',null,null,null),
('ethio-telecom','Ethio Telecom','ET','636-01',null,null,null),
('vodafone-eg','Vodafone Egypt','EG','602-02',null,null,null),
('etisalat-ae','Etisalat UAE','AE','424-02',null,null,null),
('du-ae','du UAE','AE','424-03',null,null,null),
('stc-sa','STC Saudi','SA','420-01',null,null,null),
('mobily-sa','Mobily','SA','420-03',null,null,null),
('ooredoo-qa','Ooredoo Qatar','QA','427-01',null,null,null),
('zain-kw','Zain Kuwait','KW','419-02',null,null,null),
('vodafone-uk','Vodafone UK','GB','234-15',null,null,null),
('ee-uk','EE','GB','234-30',null,null,null),
('o2-uk','O2','GB','234-10',null,null,null),
('deutsche-telekom','Deutsche Telekom','DE','262-01',null,null,null),
('vodafone-de','Vodafone Germany','DE','262-02',null,null,null),
('orange-fr','Orange France','FR','208-01',null,null,null),
('sfr-fr','SFR','FR','208-10',null,null,null),
('kpn-nl','KPN','NL','204-08',null,null,null),
('telefonica-es','Telefónica','ES','214-07',null,null,null),
('tim-it','TIM','IT','222-01',null,null,null),
('swisscom-ch','Swisscom','CH','228-01',null,null,null),
('ntt-jp','NTT Docomo','JP','440-10',null,null,null),
('kddi-jp','KDDI','JP','440-51',null,null,null),
('softbank-jp','SoftBank','JP','440-20',null,null,null),
('sk-kr','SK Telecom','KR','450-05',null,null,null),
('kt-kr','KT','KR','450-08',null,null,null),
('jio-in','Jio','IN','405-70',null,null,null),
('airtel-in','Airtel India','IN','404-10',null,null,null),
('singtel-sg','Singtel','SG','525-01',null,null,null),
('starhub-sg','StarHub','SG','525-05',null,null,null),
('telenor-pk','Telenor Pakistan','PK','410-04',null,null,null),
('grameenphone-bd','Grameenphone','BD','470-01',null,null,null),
('telkomsel-id','Telkomsel','ID','510-10',null,null,null),
('telstra-au','Telstra','AU','505-01',null,null,null),
('optus-au','Optus','AU','505-02',null,null,null),
('att-us','AT&T','US','310-410',null,null,null),
('verizon-us','Verizon','US','311-480',null,null,null),
('tmobile-us','T-Mobile US','US','310-260',null,null,null),
('rogers-ca','Rogers','CA','302-720',null,null,null),
('bell-ca','Bell','CA','302-610',null,null,null),
('claro-br','Claro Brazil','BR','724-05',null,null,null),
('vivo-br','Vivo Brazil','BR','724-06',null,null,null),
('telcel-mx','Telcel','MX','334-020',null,null,null),
('entel-cl','Entel Chile','CL','730-01',null,null,null)
on conflict (id) do update set
    name=excluded.name,country=excluded.country,mcc_mnc=excluded.mcc_mnc;

insert into lens_channel_catalog (id,platform,handle,language,countries,categories) values
('tg-naija-scamwatch','telegram','scamwatch_ng','en',array['NG'],array['scam','fraud']),
('tg-lagos-cyber','telegram','lagos_cyber','en',array['NG'],array['breach']),
('tg-kenya-fraud','telegram','kenyafraudwatch','en',array['KE'],array['scam']),
('tg-sa-fraud','telegram','safraudwatch','en',array['ZA'],array['fraud']),
('tg-ghana-scam','telegram','ghana_scam','en',array['GH'],array['scam']),
('tg-uae-cyber','telegram','uaecyber','ar',array['AE'],array['breach','scam']),
('tg-arab-cyber','telegram','arab_cyber','ar',array['AE','SA','QA'],array['breach']),
('tg-de-scam','telegram','de_scam','de',array['DE'],array['scam','fraud']),
('tg-uk-fraud','telegram','uk_fraud','en',array['GB'],array['fraud','breach']),
('tg-fr-fraude','telegram','fraude_fr','fr',array['FR'],array['fraud']),
('tg-india-cyber','telegram','indiacyber','en',array['IN'],array['breach','scam']),
('tg-jp-cyber','telegram','jp_cyber','ja',array['JP'],array['breach']),
('tg-id-scam','telegram','id_scam','id',array['ID'],array['scam','fraud']),
('tg-cn-breach','telegram','cn_breach','zh',array['CN'],array['breach']),
('tg-ransomware-live','telegram','ransomware_live','en',array[]::text[],array['ransomware']),
('tg-combolist-mirror','telegram','combolist_mirror','en',array[]::text[],array['breach','credentials']),
('tg-fraud-forum','telegram','fraud_forum','en',array[]::text[],array['fraud','scam'])
on conflict (id) do update set
    platform=excluded.platform,handle=excluded.handle,language=excluded.language,
    countries=excluded.countries,categories=excluded.categories;

-- Catalog entries are reference data; tenants explicitly subscribe to channels.
-- No automatic subscription is created here.
