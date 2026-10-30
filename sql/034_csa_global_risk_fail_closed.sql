-- Fail-closed correction: do not generate a medium default score without a CVE.
-- This follow-up is required because the initial global-risk function used a
-- generic baseline when no vulnerability identifier was supplied.

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
       or p_asset_criticality not between 1 and 5
       or p_control_exposure not between 1 and 5 then
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

    if p_cve_id is null then
        v_data_state := 'cve_required_for_vulnerability_risk';
        v_score := null;
        v_priority := 'DATA_REQUIRED';
    elsif v_kev is true then
        v_score := 10.0;
        v_priority := 'IMMEDIATE_ACTION';
    elsif v_data_state <> 'available' then
        v_score := null;
        v_priority := 'DATA_REQUIRED';
    else
        v_base := coalesce(v_cvss, 5.0);
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
