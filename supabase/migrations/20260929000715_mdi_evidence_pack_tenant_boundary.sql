begin;

create or replace function public.mdi_build_evidence_pack(p_case uuid, p_actor uuid)
returns uuid
language plpgsql
security invoker
set search_path=public
as $function$
declare
  v_payload jsonb;
  v_id uuid;
  v_tenant_id uuid;
begin
  select c.tenant_id
    into v_tenant_id
  from public.crime_cases c
  where c.id = p_case;

  if v_tenant_id is null then
    raise exception 'mdi_evidence_case_not_found_or_tenant_missing';
  end if;

  select jsonb_build_object(
    'case_id', p_case,
    'observations',
      coalesce(
        (
          select jsonb_agg(to_jsonb(x))
          from (
            select id, subject_id, observed_at, signal_type, confidence, evidence_ref
            from public.mdi_location_signals
            where case_id = p_case
            order by observed_at
          ) x
        ),
        '[]'::jsonb
      ),
    'rf_threats',
      coalesce(
        (
          select jsonb_agg(to_jsonb(x))
          from (
            select id, observation_id, threat_type, severity, confidence, algorithm, explanation
            from public.mdi_rf_threats
            where case_id = p_case
            order by created_at
          ) x
        ),
        '[]'::jsonb
      )
  )
  into v_payload;

  insert into public.mdi_evidence_packs(
    tenant_id,
    case_id,
    payload,
    sha256,
    created_by,
    chain_of_custody
  )
  values(
    v_tenant_id,
    p_case,
    v_payload,
    encode(digest(v_payload::text,'sha256'),'hex'),
    p_actor,
    jsonb_build_array(jsonb_build_object('actor',p_actor,'at',now()))
  )
  returning id into v_id;

  return v_id;
end
$function$;

revoke execute on function public.mdi_build_evidence_pack(uuid,uuid)
  from public, anon, authenticated;
grant execute on function public.mdi_build_evidence_pack(uuid,uuid)
  to service_role;

commit;