create table if not exists lens_identities (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 entity_id uuid references chauliodus_entities(id) on delete set null,
 kind text not null check (kind in ('person','executive','employee','company','brand','domain')),
 full_name text,
 name_hash text not null,
 name_phonetic text,
 emails text[] not null default '{}',
 phones text[] not null default '{}',
 domains text[] not null default '{}',
 company text,
 country text,
 role text,
 photo_ref text,
 photo_phash text,
 photo_face_hash text,
 notify_emails text[] not null default '{}',
 notify_channels text[] not null default array['critical'],
 severity_min text not null default 'medium' check (severity_min in ('info','low','medium','high','critical')),
 enabled boolean not null default true,
 created_by uuid references auth.users(id) on delete set null,
 created_at timestamptz not null default now()
);
create index if not exists idx_lens_identities_tenant on lens_identities(tenant_id, enabled);
create index if not exists idx_lens_identities_hash on lens_identities(tenant_id, name_hash);
create index if not exists idx_lens_identities_phonetic on lens_identities(tenant_id, name_phonetic);
alter table lens_identities enable row level security;
drop policy if exists lens_identities_tenant on lens_identities;
create policy lens_identities_tenant on lens_identities to authenticated using (tenant_id = (auth.jwt()->>'tenant_id')::uuid) with check (tenant_id = (auth.jwt()->>'tenant_id')::uuid);

create table if not exists lens_watch_queries (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 identity_id uuid not null references lens_identities(id) on delete cascade,
 layer text not null check (layer in ('surface','deep','dark')),
 query text not null check (length(query) between 1 and 1000),
 engine text,
 locale text,
 region text,
 crawl_interval int not null default 3600 check (crawl_interval between 300 and 604800),
 enabled boolean not null default true,
 last_run_at timestamptz,
 last_status text,
 created_at timestamptz not null default now()
);
create index if not exists idx_lens_queries_identity on lens_watch_queries(tenant_id, identity_id, enabled);
alter table lens_watch_queries enable row level security;
drop policy if exists lens_queries_tenant on lens_watch_queries;
create policy lens_queries_tenant on lens_watch_queries to authenticated using (tenant_id = (auth.jwt()->>'tenant_id')::uuid) with check (tenant_id = (auth.jwt()->>'tenant_id')::uuid);

create table if not exists lens_findings (
 id bigserial primary key,
 tenant_id uuid not null references tenants(id) on delete cascade,
 identity_id uuid not null references lens_identities(id) on delete cascade,
 query_id uuid references lens_watch_queries(id) on delete set null,
 layer text not null check (layer in ('surface','deep','dark')),
 source text not null,
 title text,
 url text,
 snippet text,
 content_hash text not null,
 language text,
 country text,
 matched_on text not null check (matched_on in ('name','email','phone','domain','photo')),
 match_score real not null default 0 check (match_score between 0 and 1),
 match_kind text not null check (match_kind in ('exact','fuzzy','phonetic','email','phone','domain','photo','context')),
 snapshot_ref text,
 screenshot_ref text,
 metadata jsonb not null default '{}'::jsonb,
 severity text not null default 'medium' check (severity in ('info','low','medium','high','critical')),
 first_seen timestamptz not null default now(),
 unique (tenant_id, content_hash)
);
create index if not exists idx_lens_findings_identity on lens_findings(tenant_id, identity_id, first_seen desc);
alter table lens_findings enable row level security;
drop policy if exists lens_findings_tenant on lens_findings;
create policy lens_findings_tenant on lens_findings to authenticated using (tenant_id = (auth.jwt()->>'tenant_id')::uuid) with check (tenant_id = (auth.jwt()->>'tenant_id')::uuid);

create table if not exists lens_alerts (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 identity_id uuid not null references lens_identities(id) on delete cascade,
 finding_id bigint not null references lens_findings(id) on delete cascade,
 title text not null,
 summary text,
 severity text not null check (severity in ('info','low','medium','high','critical')),
 status text not null default 'new' check (status in ('new','acknowledged','actioned','dismissed','false_positive')),
 takedown_url text,
 takedown_status text,
 case_id uuid references crime_cases(id) on delete set null,
 acknowledged_at timestamptz,
 resolved_at timestamptz,
 created_at timestamptz not null default now(),
 unique (tenant_id, finding_id)
);
create index if not exists idx_lens_alerts_tenant on lens_alerts(tenant_id, created_at desc);
alter table lens_alerts enable row level security;
drop policy if exists lens_alerts_tenant on lens_alerts;
create policy lens_alerts_tenant on lens_alerts to authenticated using (tenant_id = (auth.jwt()->>'tenant_id')::uuid) with check (tenant_id = (auth.jwt()->>'tenant_id')::uuid);

create table if not exists lens_stats (
 tenant_id uuid not null references tenants(id) on delete cascade,
 day date not null,
 findings_total int not null default 0,
 alerts_total int not null default 0,
 surface_count int not null default 0,
 deep_count int not null default 0,
 dark_count int not null default 0,
 primary key (tenant_id, day)
);
alter table lens_stats enable row level security;
drop policy if exists lens_stats_tenant on lens_stats;
create policy lens_stats_tenant on lens_stats to authenticated using (tenant_id = (auth.jwt()->>'tenant_id')::uuid) with check (tenant_id = (auth.jwt()->>'tenant_id')::uuid);

create or replace function lens_set_photo_fingerprint(p_tenant uuid,p_identity uuid,p_phash text)
returns void language plpgsql security definer set search_path=public as $$
begin
 if p_phash is null or length(p_phash) <> 16 or p_phash !~ '^[0-9a-f]{16}$' then raise exception 'invalid photo fingerprint'; end if;
 if not exists(select 1 from lens_identities where id=p_identity and tenant_id=p_tenant) then raise exception 'identity not found'; end if;
 update lens_identities set photo_phash=p_phash, photo_ref=null where id=p_identity and tenant_id=p_tenant;
end $$;
revoke all on function lens_set_photo_fingerprint(uuid,uuid,text) from public;
grant execute on function lens_set_photo_fingerprint(uuid,uuid,text) to service_role;

create or replace function lens_record_finding(
 p_tenant uuid,p_identity uuid,p_query uuid,p_layer text,p_source text,p_title text,p_url text,
 p_snippet text,p_content_hash text,p_language text,p_country text,p_matched_on text,p_match_score real,
 p_match_kind text,p_snapshot_ref text,p_metadata jsonb,p_severity text)
returns bigint language plpgsql security definer set search_path=public as $$
declare v_id bigint;
begin
 if not exists(select 1 from lens_identities where id=p_identity and tenant_id=p_tenant) then raise exception 'identity tenant mismatch'; end if;
 if p_query is not null and not exists(select 1 from lens_watch_queries where id=p_query and tenant_id=p_tenant and identity_id=p_identity) then raise exception 'query tenant mismatch'; end if;
 insert into lens_findings(tenant_id,identity_id,query_id,layer,source,title,url,snippet,content_hash,language,country,matched_on,match_score,match_kind,snapshot_ref,metadata,severity)
 values(p_tenant,p_identity,p_query,p_layer,p_source,p_title,p_url,p_snippet,p_content_hash,p_language,p_country,p_matched_on,p_match_score,p_match_kind,p_snapshot_ref,coalesce(p_metadata,'{}'),p_severity)
 on conflict(tenant_id,content_hash) do nothing returning id into v_id;
 if v_id is null then select id into v_id from lens_findings where tenant_id=p_tenant and content_hash=p_content_hash; end if;
 if v_id is not null then
   insert into lens_stats(tenant_id,day,findings_total,surface_count,deep_count,dark_count)
   values(p_tenant,current_date,1,(p_layer='surface')::int,(p_layer='deep')::int,(p_layer='dark')::int)
   on conflict(tenant_id,day) do update set findings_total=lens_stats.findings_total+1,
    surface_count=lens_stats.surface_count+(p_layer='surface')::int,
    deep_count=lens_stats.deep_count+(p_layer='deep')::int,
    dark_count=lens_stats.dark_count+(p_layer='dark')::int;
 end if;
 return v_id;
end $$;
revoke all on function lens_record_finding(uuid,uuid,uuid,text,text,text,text,text,text,text,text,text,real,text,text,jsonb,text) from public;
grant execute on function lens_record_finding(uuid,uuid,uuid,text,text,text,text,text,text,text,text,text,real,text,text,jsonb,text) to service_role;
