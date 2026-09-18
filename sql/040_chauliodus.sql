create table if not exists chauliodus_numbers (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 e164 text not null, e164_hash text not null, country text not null, country_code text not null, national text not null,
 line_type text check (line_type in ('mobile','landline','voip','tollfree','unknown')), carrier text, carrier_mcc_mnc text,
 is_ported boolean, voip_probability real not null default 0 check (voip_probability between 0 and 1),
 recycling_score real not null default 0 check (recycling_score between 0 and 1),
 fraud_score real not null default 0 check (fraud_score between 0 and 1),
 first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
 metadata jsonb not null default '{}'::jsonb, unique (tenant_id,e164_hash)
);
create index if not exists idx_ch_numbers_hash on chauliodus_numbers(e164_hash);
create index if not exists idx_ch_numbers_tenant on chauliodus_numbers(tenant_id,last_seen desc);
create index if not exists idx_ch_numbers_fraud on chauliodus_numbers(tenant_id,fraud_score desc);
alter table chauliodus_numbers enable row level security;
drop policy if exists chauliodus_numbers_tenant on chauliodus_numbers;
create policy chauliodus_numbers_tenant on chauliodus_numbers using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists chauliodus_entities (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 kind text not null check (kind in ('phone','email','wallet','domain','ip','device','person','org','bank_account','telegram','username','photo_hash','voice_hash','certificate')),
 value_hash text not null, value_redacted text, value_encrypted text, encryption_ref text,
 first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
 confidence real not null default 0.5 check (confidence between 0 and 1), metadata jsonb not null default '{}'::jsonb,
 unique (tenant_id,kind,value_hash)
);
create index if not exists idx_ch_entities_hash on chauliodus_entities(tenant_id,kind,value_hash);
create index if not exists idx_ch_entities_kind on chauliodus_entities(tenant_id,kind,last_seen desc);
alter table chauliodus_entities enable row level security;
drop policy if exists chauliodus_entities_tenant on chauliodus_entities;
create policy chauliodus_entities_tenant on chauliodus_entities using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists chauliodus_edges (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 source_id uuid not null references chauliodus_entities(id) on delete cascade, target_id uuid not null references chauliodus_entities(id) on delete cascade,
 relation text not null check (relation in ('uses','owns','controls','contacted','paid','registered','hosted_on','resolved_to','member_of','communicated_with','associated_with','observed_with')),
 weight real not null default 1.0 check (weight between 0 and 1), confidence real not null default 0.5 check (confidence between 0 and 1),
 evidence_count int not null default 1, sources text[] not null default '{}',
 first_seen timestamptz not null default now(), last_seen timestamptz not null default now(),
 unique (source_id,target_id,relation)
);
create index if not exists idx_ch_edges_source on chauliodus_edges(source_id,weight desc);
create index if not exists idx_ch_edges_target on chauliodus_edges(target_id,weight desc);
create index if not exists idx_ch_edges_tenant on chauliodus_edges(tenant_id);
alter table chauliodus_edges enable row level security;
drop policy if exists chauliodus_edges_tenant on chauliodus_edges;
create policy chauliodus_edges_tenant on chauliodus_edges using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists chauliodus_attributions (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references tenants(id) on delete cascade,
 requested_by uuid references auth.users(id) on delete set null, input_kind text not null, input_hash text not null,
 case_id uuid references crime_cases(id) on delete set null, status text not null default 'pending' check (status in ('pending','running','complete','failed')),
 result jsonb, confidence real, duration_ms int, error text, created_at timestamptz not null default now(), completed_at timestamptz
);
create index if not exists idx_ch_attr_tenant on chauliodus_attributions(tenant_id,created_at desc);
create index if not exists idx_ch_attr_hash on chauliodus_attributions(tenant_id,input_hash);
alter table chauliodus_attributions enable row level security;
drop policy if exists chauliodus_attr_tenant on chauliodus_attributions;
create policy chauliodus_attr_tenant on chauliodus_attributions using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create table if not exists chauliodus_signals (
 id bigserial primary key, tenant_id uuid not null, entity_id uuid references chauliodus_entities(id) on delete cascade,
 signal_type text not null, source text not null, severity text not null default 'medium',
 observed_at timestamptz not null default now(), payload jsonb not null default '{}'::jsonb
);
create index if not exists idx_ch_signals_entity on chauliodus_signals(entity_id,observed_at desc);
create index if not exists idx_ch_signals_tenant on chauliodus_signals(tenant_id,observed_at desc);
alter table chauliodus_signals enable row level security;
drop policy if exists chauliodus_signals_tenant on chauliodus_signals;
create policy chauliodus_signals_tenant on chauliodus_signals using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create or replace function chauliodus_upsert_entity(p_tenant uuid,p_kind text,p_value_hash text,p_value_redacted text,p_value_encrypted text,p_encryption_ref text)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 insert into chauliodus_entities(tenant_id,kind,value_hash,value_redacted,value_encrypted,encryption_ref)
 values(p_tenant,p_kind,p_value_hash,p_value_redacted,p_value_encrypted,p_encryption_ref)
 on conflict(tenant_id,kind,value_hash) do update set last_seen=now() returning id into v_id;
 return v_id;
end $$;
revoke all on function chauliodus_upsert_entity(uuid,text,text,text,text,text) from public,anon,authenticated;
grant execute on function chauliodus_upsert_entity(uuid,text,text,text,text,text) to service_role;

create or replace function chauliodus_upsert_edge(p_tenant uuid,p_source uuid,p_target uuid,p_relation text,p_weight real,p_confidence real,p_source_tag text)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 if not exists(select 1 from chauliodus_entities where id=p_source and tenant_id=p_tenant) or
    not exists(select 1 from chauliodus_entities where id=p_target and tenant_id=p_tenant) then
   raise exception 'cross-tenant entity reference';
 end if;
 insert into chauliodus_edges(tenant_id,source_id,target_id,relation,weight,confidence,sources)
 values(p_tenant,p_source,p_target,p_relation,p_weight,p_confidence,array[p_source_tag])
 on conflict(source_id,target_id,relation) do update set
   weight=least(1.0,chauliodus_edges.weight+(excluded.weight*0.15)),
   confidence=greatest(chauliodus_edges.confidence,excluded.confidence),
   evidence_count=chauliodus_edges.evidence_count+1,
   sources=(select array_agg(distinct x) from unnest(chauliodus_edges.sources||excluded.sources) as x),
   last_seen=now()
 returning id into v_id;
 return v_id;
end $$;
revoke all on function chauliodus_upsert_edge(uuid,uuid,uuid,text,real,real,text) from public,anon,authenticated;
grant execute on function chauliodus_upsert_edge(uuid,uuid,uuid,text,real,real,text) to service_role;

create or replace function chauliodus_check_rate(p_tenant uuid,p_limit int default 100,p_window_seconds int default 3600)
returns boolean language plpgsql security definer set search_path=public as $$
declare v_count int;
begin
 select count(*) into v_count from chauliodus_attributions where tenant_id=p_tenant
   and created_at > now()-(p_window_seconds||' seconds')::interval;
 return v_count<p_limit;
end $$;
revoke all on function chauliodus_check_rate(uuid,int,int) from public,anon,authenticated;
grant execute on function chauliodus_check_rate(uuid,int,int) to service_role;
