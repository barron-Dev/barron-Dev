-- CSA global intelligence: source-attributed exploit data and sovereign mappings.
-- Additive migration. Global feed rows are service-written; tenant risk decisions
-- are tenant-scoped and never treat unavailable intelligence as a clean result.

create table if not exists public.csa_global_intel_sync_runs (
    id uuid primary key default gen_random_uuid(),
    source text not null check (source in ('cisa_kev','first_epss')),
    started_at timestamptz not null default now(),
    completed_at timestamptz,
    status text not null check (status in ('running','succeeded','partial','failed')),
    records_seen integer not null default 0 check (records_seen >= 0),
    records_upserted integer not null default 0 check (records_upserted >= 0),
    source_version text,
    source_as_of date,
    error_code text,
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object')
);

create table if not exists public.csa_global_exploit_intel (
    cve_id text primary key check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    cisa_kev_listed boolean not null default false,
    kev_date_added date,
    kev_due_date date,
    known_ransomware_use boolean not null default false,
    epss_score double precision check (epss_score is null or (epss_score >= 0 and epss_score <= 1)),
    epss_percentile double precision check (epss_percentile is null or (epss_percentile >= 0 and epss_percentile <= 1)),
    cvss_base_score double precision check (cvss_base_score is null or (cvss_base_score >= 0 and cvss_base_score <= 10)),
    epss_as_of date,
    kev_synced_at timestamptz,
    epss_synced_at timestamptz,
    source_refs jsonb not null default '{}'::jsonb check (jsonb_typeof(source_refs) = 'object'),
    updated_at timestamptz not null default now()
);
create index if not exists csa_global_exploit_intel_epss_idx
    on public.csa_global_exploit_intel (epss_score desc nulls last);
create index if not exists csa_global_exploit_intel_kev_idx
    on public.csa_global_exploit_intel (cisa_kev_listed, kev_date_added desc);

create table if not exists public.csa_sovereign_frameworks (
    framework_key text primary key,
    country_iso char(2) not null,
    framework_name text not null,
    framework_version text not null,
    authority_name text not null,
    source_url text not null,
    source_version text,
    evaluation_frequency_days integer check (evaluation_frequency_days is null or evaluation_frequency_days > 0),
    jurisdiction_level text not null default 'national',
    caveats text,
    active boolean not null default true,
    updated_at timestamptz not null default now()
);

create table if not exists public.csa_sovereign_framework_mapping (
    id uuid primary key default gen_random_uuid(),
    framework_key text not null references public.csa_sovereign_frameworks(framework_key),
    cyclothone_control_id text not null,
    external_control_id text not null,
    external_control_title text not null,
    mapping_method text not null check (mapping_method in ('explicit','crosswalk','candidate')),
    mapping_confidence double precision check (mapping_confidence is null or (mapping_confidence >= 0 and mapping_confidence <= 1)),
    source_url text not null,
    source_version text not null,
    reviewed_at timestamptz,
    review_status text not null default 'unreviewed' check (review_status in ('unreviewed','reviewed','rejected')),
    evaluation_frequency_days integer check (evaluation_frequency_days is null or evaluation_frequency_days > 0),
    unique (framework_key, cyclothone_control_id, external_control_id)
);
create index if not exists csa_sovereign_mapping_control_idx
    on public.csa_sovereign_framework_mapping (cyclothone_control_id, framework_key);

alter table public.csa_global_intel_sync_runs enable row level security;
alter table public.csa_global_exploit_intel enable row level security;
alter table public.csa_sovereign_frameworks enable row level security;
alter table public.csa_sovereign_framework_mapping enable row level security;

revoke all on public.csa_global_intel_sync_runs, public.csa_global_exploit_intel,
    public.csa_sovereign_frameworks, public.csa_sovereign_framework_mapping
    from public, anon, authenticated;
grant select on public.csa_global_exploit_intel, public.csa_sovereign_frameworks,
    public.csa_sovereign_framework_mapping to authenticated;
grant select, insert, update on public.csa_global_intel_sync_runs to service_role;
grant select, insert, update on public.csa_global_exploit_intel to service_role;
grant select, insert, update, delete on public.csa_sovereign_frameworks,
    public.csa_sovereign_framework_mapping to service_role;

create policy csa_global_exploit_intel_authenticated_read
    on public.csa_global_exploit_intel for select to authenticated using (true);
create policy csa_sovereign_frameworks_authenticated_read
    on public.csa_sovereign_frameworks for select to authenticated using (true);
create policy csa_sovereign_mapping_authenticated_read
    on public.csa_sovereign_framework_mapping for select to authenticated using (true);

-- Jurisdiction registry. Frequency values are left NULL where an authoritative,
-- universal cadence is not established by this registry; sector/system-level
-- rules and current law still require jurisdiction-specific review.
insert into public.csa_sovereign_frameworks
(framework_key,country_iso,framework_name,framework_version,authority_name,source_url,source_version,evaluation_frequency_days,caveats)
values
('US_NIST_CSF_2_0','US','NIST Cybersecurity Framework','2.0','NIST','https://www.nist.gov/cyberframework','CSF 2.0',null,'Risk-management framework; not a universal certification schedule.'),
('US_CISA_KEV','US','Known Exploited Vulnerabilities Catalog','current','CISA','https://www.cisa.gov/known-exploited-vulnerabilities-catalog','live catalog',null,'Vulnerability prioritization input; not a control framework.'),
('US_FIRST_EPSS','US','Exploit Prediction Scoring System','current','FIRST','https://www.first.org/epss/','daily scores',null,'EPSS is a 30-day exploitation probability estimate for CVEs, not a tenant breach probability.'),
('DE_BSI_IT_GRUNDSCHUTZ','DE','BSI IT-Grundschutz','current','BSI','https://www.bsi.bund.de/EN/Themes/ITGrundschutz/itgrundschutz_node.html','current edition',null,'Module selection and risk analysis depend on scope and BSI methodology.'),
('CN_MLPS_2_0','CN','Multi-Level Protection Scheme','MLPS 2.0','China public security authorities','https://www.gov.cn/','GB/T 22239-2019',null,'Classification, filing and assessment duties depend on system level and applicable rules; verify current local requirements.'),
('RU_FSTEC_ORDER_31','RU','FSTEC Order No. 31','current','FSTEC','https://fstec.ru/','current consolidated text',null,'Applicability depends on regulated system category and current Russian requirements.')
on conflict (framework_key) do update set
 framework_name=excluded.framework_name, framework_version=excluded.framework_version,
 authority_name=excluded.authority_name, source_url=excluded.source_url,
 source_version=excluded.source_version, caveats=excluded.caveats, updated_at=now();

-- NIST CSF 2.0 function-level crosswalk candidates only. They are explicitly
-- unreviewed and carry no legal-equivalence claim until control-level validation.
insert into public.csa_sovereign_framework_mapping
(framework_key,cyclothone_control_id,external_control_id,external_control_title,mapping_method,mapping_confidence,source_url,source_version,review_status)
values
('US_NIST_CSF_2_0','soc2.CC8.1','GV','Govern','candidate',null,'https://www.nist.gov/cyberframework','2.0','unreviewed'),
('US_NIST_CSF_2_0','soc2.CC6.1','PR','Protect','candidate',null,'https://www.nist.gov/cyberframework','2.0','unreviewed'),
('US_NIST_CSF_2_0','soc2.CC6.6','PR','Protect','candidate',null,'https://www.nist.gov/cyberframework','2.0','unreviewed'),
('US_NIST_CSF_2_0','soc2.CC7.1','DE','Detect','candidate',null,'https://www.nist.gov/cyberframework','2.0','unreviewed'),
('US_NIST_CSF_2_0','soc2.CC7.2','RS','Respond','candidate',null,'https://www.nist.gov/cyberframework','2.0','unreviewed'),
('US_NIST_CSF_2_0','soc2.CC9.1','RC','Recover','candidate',null,'https://www.nist.gov/cyberframework','2.0','unreviewed')
on conflict (framework_key,cyclothone_control_id,external_control_id) do nothing;

-- A North Korea entry is intentionally not seeded: no public, officially
-- recognized national cybersecurity certification framework was established
-- by the reviewed public source set for this product release.

create or replace function public.calculate_csa_global_risk(
    p_tenant_id uuid,
    p_control_id text,
    p_cve_id text default null,
    p_asset_criticality integer default 3,
    p_control_exposure integer default 3
) returns jsonb
language plpgsql
stable
security invoker
set search_path = pg_catalog, public
as $$
declare
    v_epss double precision;
    v_kev boolean := false;
    v_cvss double precision;
    v_kev_date date;
    v_epss_as_of date;
    v_feed_updated timestamptz;
    v_data_state text := 'not_applicable';
    v_score double precision;
    v_priority text;
    v_base double precision;
begin
    if p_tenant_id is null or p_control_id is null or length(trim(p_control_id)) = 0 then
        raise exception 'tenant_and_control_required';
    end if;
    if p_asset_criticality is null or p_control_exposure is null
       or p_asset_criticality not between 1 and 5 or p_control_exposure not between 1 and 5 then
        raise exception 'criticality_and_exposure_must_be_1_to_5';
    end if;
    if coalesce(auth.jwt() ->> 'role','') <> 'service_role'
       and nullif(auth.jwt() ->> 'tenant_id','')::uuid is distinct from p_tenant_id then
        raise exception 'tenant_scope_denied' using errcode = '42501';
    end if;

    if p_cve_id is not null then
        select epss_score, cisa_kev_listed, cvss_base_score, kev_date_added,
               epss_as_of, greatest(kev_synced_at, epss_synced_at)
          into v_epss, v_kev, v_cvss, v_kev_date, v_epss_as_of, v_feed_updated
          from public.csa_global_exploit_intel
         where cve_id = upper(trim(p_cve_id));
        if not found then
            v_data_state := 'cve_not_in_synced_dataset';
        elsif v_epss is null and not v_kev then
            v_data_state := 'epss_unavailable';
        else
            v_data_state := 'available';
        end if;
    end if;

    if v_kev then
        v_score := 10.0;
        v_priority := 'IMMEDIATE_ACTION';
    elsif p_cve_id is not null and v_data_state <> 'available' then
        v_score := null;
        v_priority := 'DATA_REQUIRED';
    else
        v_base := coalesce(v_cvss, 5.0);
        -- Deterministic risk indicator: CVSS severity × asset criticality ×
        -- exposure, with EPSS as a threat-likelihood multiplier. Not a breach
        -- probability and not a replacement for the full CSA control assessment.
        v_score := least(9.9, greatest(0.1,
            (v_base * (0.6 + (p_asset_criticality * 0.08) + (p_control_exposure * 0.06))
             * (case when v_epss > 0.50 then 1.35 when v_epss > 0.10 then 1.15 else 1.0 end)
            )));
        v_priority := case when v_score >= 8 then 'HIGH'
                           when v_score >= 5 then 'MEDIUM' else 'LOW' end;
    end if;

    return jsonb_build_object(
        'tenant_id', p_tenant_id,
        'control_id', p_control_id,
        'associated_cve', p_cve_id,
        'intelligence_state', v_data_state,
        'is_actively_exploited', v_kev,
        'epss_probability_30d', v_epss,
        'cvss_base_score', v_cvss,
        'kev_date_added', v_kev_date,
        'epss_as_of', v_epss_as_of,
        'feed_updated_at', v_feed_updated,
        'asset_criticality', p_asset_criticality,
        'control_exposure', p_control_exposure,
        'calculated_risk_indicator', round(v_score::numeric, 2),
        'remediation_priority', v_priority,
        'probability_semantics', 'EPSS is CVE-level 30-day exploitation probability; this indicator is not tenant breach probability.',
        'evaluation_timestamp', now()
    );
end;
$$;

revoke all on function public.calculate_csa_global_risk(uuid,text,text,integer,integer) from public, anon;
grant execute on function public.calculate_csa_global_risk(uuid,text,text,integer,integer) to authenticated, service_role;

comment on table public.csa_global_exploit_intel is
 'Source-attributed CISA KEV and FIRST EPSS observations. Missing feed data is unknown, never a zero-risk assertion.';
comment on table public.csa_sovereign_framework_mapping is
 'Versioned candidate crosswalks; mapping confidence and review status remain explicit.';
