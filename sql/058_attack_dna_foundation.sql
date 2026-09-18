-- sql/058_attack_dna_foundation.sql
-- Cyclothone Attack DNA: immutable evidence foundation.
-- This is an attribution evidence system, not a biological identification claim.

create table dna_traits (
    id text primary key,
    category text not null check (category in (
        'tooling','timing','targeting','language','crypto',
        'infrastructure','ttp','artifact','voice','visual','behavioral'
    )),
    name text not null,
    description text,
    dimension int not null check (dimension between 1 and 4096),
    weight real not null default 1.0 check (weight > 0 and weight <= 1),
    enabled boolean not null default true
);

insert into dna_traits (id,category,name,description,dimension,weight) values
('ttp.mitre_set','ttp','MITRE technique set','ATT&CK technique combination',128,0.90),
('tooling.malware_family','tooling','Malware family','Stable family/reuse indicators',64,0.85),
('tooling.tool_stack','tooling','Tool stack','Observed tooling combination',32,0.80),
('timing.beacon_interval','timing','Beacon interval','C2 callback timing distribution',16,0.75),
('timing.activity_hours','timing','Activity hours','UTC activity distribution',24,0.60),
('targeting.sector','targeting','Target sector','Observed sector targeting',32,0.70),
('targeting.geography','targeting','Target geography','Observed target geography',48,0.65),
('language.idioms','language','Language markers','Lexical/style markers',64,0.70),
('language.grammar_errors','language','Language error signature','Observed recurring linguistic patterns',32,0.55),
('crypto.address_pattern','crypto','Crypto address pattern','Address/reuse characteristics',32,0.80),
('crypto.ransom_note_style','crypto','Ransom note style','Document/template similarity',48,0.75),
('infrastructure.asn','infrastructure','ASN preference','Observed ASN reuse',32,0.70),
('infrastructure.domain_pattern','infrastructure','Domain pattern','Registration/DGA characteristics',48,0.70),
('infrastructure.cert_reuse','infrastructure','Certificate reuse','Certificate fingerprint overlap',32,0.75),
('artifact.file_metadata','artifact','File metadata','Compiler/linker/build metadata',48,0.80),
('artifact.mutex','artifact','Mutex names','Observed mutex reuse',32,0.70),
('voice.prosody','voice','Voice prosody','Extracted prosodic characteristics',48,0.65),
('visual.logo_phash','visual','Logo perceptual hash','Visual artifact similarity',32,0.60),
('behavioral.process_tree','behavioral','Process tree shape','Parent/child execution graph',128,0.85),
('behavioral.timing_signature','behavioral','Timing signature','Stage-to-stage delay pattern',64,0.75)
on conflict (id) do update set category=excluded.category,name=excluded.name,
description=excluded.description,dimension=excluded.dimension,weight=excluded.weight;

create table dna_signatures (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    kind text not null check (kind in ('actor','campaign','family','incident')),
    name text not null check (length(name) between 1 and 256),
    aliases text[] not null default '{}',
    vector real[] not null,
    vector_dim int not null check (vector_dim > 0),
    traits jsonb not null default '{}'::jsonb,
    trait_count int not null default 0 check (trait_count between 0 and 64),
    confidence real not null default 0.5 check (confidence between 0 and 1),
    origin_country text,
    motivation text,
    first_seen timestamptz,
    last_seen timestamptz,
    status text not null default 'unconfirmed'
        check (status in ('active','retired','merged','unconfirmed')),
    merged_into uuid references dna_signatures(id) on delete set null,
    extractor_version text not null default 'rules-v1',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check (vector_dim = coalesce(array_length(vector,1),0)),
    check (jsonb_typeof(traits) = 'object')
);
create index idx_dna_sig_tenant_status on dna_signatures(tenant_id,status);
create index idx_dna_sig_kind on dna_signatures(tenant_id,kind);

create table dna_fingerprints (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    source_kind text not null check (source_kind in (
        'detection','case','scam_report','darkweb','brand','physical'
    )),
    source_id text not null check (length(source_id) between 1 and 256),
    vector real[] not null,
    vector_dim int not null check (vector_dim > 0),
    traits jsonb not null default '{}'::jsonb,
    trait_ids text[] not null default '{}',
    confidence real not null check (confidence between 0 and 1),
    coverage real not null check (coverage between 0 and 1),
    extractor_version text not null default 'rules-v1',
    schema_hash text not null,
    observed_at timestamptz not null default now(),
    created_at timestamptz not null default now(),
    unique (tenant_id,source_kind,source_id),
    check (vector_dim = coalesce(array_length(vector,1),0)),
    check (jsonb_typeof(traits) = 'object')
);
create index idx_dna_fp_tenant_time on dna_fingerprints(tenant_id,observed_at desc);
create index idx_dna_fp_source on dna_fingerprints(tenant_id,source_kind,source_id);

create table dna_matches (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    fingerprint_id uuid not null references dna_fingerprints(id) on delete cascade,
    signature_id uuid not null references dna_signatures(id) on delete cascade,
    cosine real not null check (cosine between 0 and 1),
    jaccard real not null check (jaccard between 0 and 1),
    trait_overlap int not null check (trait_overlap between 0 and 64),
    combined real not null check (combined between 0 and 1),
    verdict text not null check (verdict in ('attribution','partial','weak','none')),
    reasons jsonb not null default '[]'::jsonb,
    algorithm_version text not null default 'fusion-v1',
    case_id uuid references crime_cases(id) on delete set null,
    created_at timestamptz not null default now()
);
create index idx_dna_match_tenant_time on dna_matches(tenant_id,created_at desc);
create index idx_dna_match_sig_score on dna_matches(signature_id,combined desc);
create index idx_dna_match_fp on dna_matches(fingerprint_id);

create table dna_campaigns (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    name text,
    fingerprint_ids uuid[] not null default '{}',
    centroid real[] not null,
    centroid_dim int not null,
    cohesion real not null check (cohesion between 0 and 1),
    size int not null check (size >= 2),
    first_seen timestamptz not null,
    last_seen timestamptz not null,
    status text not null default 'active'
        check (status in ('active','closed','merged')),
    linked_case_ids uuid[] not null default '{}',
    algorithm_version text not null default 'cluster-v1',
    created_at timestamptz not null default now(),
    check (centroid_dim = coalesce(array_length(centroid,1),0)),
    check (last_seen >= first_seen)
);
create index idx_dna_campaign_tenant_time on dna_campaigns(tenant_id,last_seen desc);

alter table dna_signatures enable row level security;
alter table dna_fingerprints enable row level security;
alter table dna_matches enable row level security;
alter table dna_campaigns enable row level security;

create policy dna_sig_read on dna_signatures for select to authenticated
using (tenant_id is null or tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));
create policy dna_fp_read on dna_fingerprints for select to authenticated
using (tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));
create policy dna_match_read on dna_matches for select to authenticated
using (tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));
create policy dna_campaign_read on dna_campaigns for select to authenticated
using (tenant_id = (select (auth.jwt()->>'tenant_id')::uuid));

revoke all on dna_traits,dna_signatures,dna_fingerprints,dna_matches,dna_campaigns
from anon,authenticated;

create or replace function dna_upsert_signature(
    p_tenant uuid, p_kind text, p_name text,
    p_vector real[], p_traits jsonb, p_trait_count int,
    p_confidence real, p_origin text, p_motivation text,
    p_extractor_version text default 'rules-v1'
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid;
begin
    if p_tenant is not null and not exists (select 1 from tenants where id=p_tenant) then
        raise exception 'unknown tenant';
    end if;
    if p_vector is null or coalesce(array_length(p_vector,1),0) = 0 then
        raise exception 'signature vector required';
    end if;
    if p_trait_count is null or p_trait_count < 0 or p_trait_count > 64 then
        raise exception 'invalid trait count';
    end if;
    if p_traits is null or jsonb_typeof(p_traits) <> 'object' then
        raise exception 'traits must be an object';
    end if;
    if p_confidence is null or p_confidence < 0 or p_confidence > 1 then
        raise exception 'invalid confidence';
    end if;
    if exists (
        select 1 from unnest(p_vector) v
        where v is null or v <> v or v = 'Infinity'::real or v = '-Infinity'::real
    ) then
        raise exception 'non-finite vector value';
    end if;

    insert into dna_signatures(
        tenant_id,kind,name,vector,vector_dim,traits,trait_count,confidence,
        origin_country,motivation,extractor_version,first_seen,last_seen
    ) values (
        p_tenant,p_kind,p_name,p_vector,array_length(p_vector,1),p_traits,p_trait_count,
        p_confidence,p_origin,p_motivation,p_extractor_version,now(),now()
    ) returning id into v_id;
    return v_id;
end;
$$;

create or replace function dna_record_match(
    p_tenant uuid,p_fp uuid,p_sig uuid,p_cosine real,p_jaccard real,
    p_overlap int,p_combined real,p_verdict text,p_reasons jsonb,p_case uuid,
    p_algorithm_version text default 'fusion-v1'
) returns uuid
language plpgsql security definer set search_path=public
as $$
declare v_id uuid; v_sig_tenant uuid; v_fp_tenant uuid; v_case_tenant uuid;
begin
    select tenant_id into v_fp_tenant from dna_fingerprints where id=p_fp;
    select tenant_id into v_sig_tenant from dna_signatures where id=p_sig;
    if v_fp_tenant is distinct from p_tenant then raise exception 'fingerprint tenant mismatch'; end if;
    if v_sig_tenant is not null and v_sig_tenant is distinct from p_tenant then raise exception 'signature tenant mismatch'; end if;
    if p_case is not null then
        select tenant_id into v_case_tenant from crime_cases where id=p_case;
        if v_case_tenant is distinct from p_tenant then raise exception 'case tenant mismatch'; end if;
    end if;
    if p_cosine is null or p_cosine < 0 or p_cosine > 1
       or p_jaccard is null or p_jaccard < 0 or p_jaccard > 1
       or p_combined is null or p_combined < 0 or p_combined > 1 then
        raise exception 'invalid DNA score';
    end if;
    insert into dna_matches(
        tenant_id,fingerprint_id,signature_id,cosine,jaccard,trait_overlap,
        combined,verdict,reasons,algorithm_version,case_id
    ) values (
        p_tenant,p_fp,p_sig,p_cosine,p_jaccard,p_overlap,p_combined,p_verdict,
        coalesce(p_reasons,'[]'::jsonb),p_algorithm_version,p_case
    ) returning id into v_id;
    return v_id;
end;
$$;

create or replace function dna_stats(p_tenant uuid)
returns jsonb language sql stable security definer set search_path=public
as $$
select jsonb_build_object(
 'signatures',(select count(*) from dna_signatures where tenant_id is null or tenant_id=p_tenant),
 'fingerprints',(select count(*) from dna_fingerprints where tenant_id=p_tenant),
 'matches',(select count(*) from dna_matches where tenant_id=p_tenant),
 'attributions',(select count(*) from dna_matches where tenant_id=p_tenant and verdict='attribution'),
 'campaigns',(select count(*) from dna_campaigns where tenant_id=p_tenant and status='active')
);
$$;

revoke all on function dna_upsert_signature(uuid,text,text,real[],jsonb,int,real,text,text,text) from public,anon,authenticated;
revoke all on function dna_record_match(uuid,uuid,uuid,real,real,int,real,text,jsonb,uuid,text) from public,anon,authenticated;
revoke all on function dna_stats(uuid) from public,anon,authenticated;
grant execute on function dna_upsert_signature(uuid,text,text,real[],jsonb,int,real,text,text,text) to service_role;
grant execute on function dna_record_match(uuid,uuid,uuid,real,real,int,real,text,jsonb,uuid,text) to service_role;
grant execute on function dna_stats(uuid) to service_role;
