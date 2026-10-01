begin;

insert into public.giril_ref_sources
(source_key,name,authority_level,source_kind,source_url,api_base_url,licensing_notes,update_policy,status)
values
('ISO_3166','ISO 3166 Maintenance Agency','PRIMARY','STANDARDS','https://www.iso.org/iso-3166-country-codes.html',null,'Country codes are free to use; bulk Country Codes Collection may require applicable licensing. Do not scrape or redistribute paid bulk data without rights.','Refresh on official change notice.','UNINITIALIZED'),
('IANA_ROOT_ZONE','IANA Root Zone Database','PRIMARY','DNS','https://www.iana.org/domains/root/db','https://data.iana.org/TLD/tlds-alpha-by-domain.txt','Use official IANA feed and preserve manifest/version.','Daily check; refresh on source version change.','UNINITIALIZED'),
('GLEIF_LEI','GLEIF LEI Data/API','PRIMARY','REGISTRY','https://www.gleif.org/en/lei-data/gleif-api/','https://api.gleif.org/api/v1','Use official GLEIF API/data terms; no synthetic LEI records.','On-demand verification; refresh on official version change.','UNINITIALIZED')
on conflict (source_key) do update set name=excluded.name,authority_level=excluded.authority_level,source_kind=excluded.source_kind,source_url=excluded.source_url,api_base_url=excluded.api_base_url,licensing_notes=excluded.licensing_notes,update_policy=excluded.update_policy,updated_at=now();

create or replace function public.giril_create_onboarding_case(p_requested_name text,p_email text,p_phone text,p_subject_kind text default null,p_country_iso2 text default null)
returns uuid language plpgsql security definer set search_path to public,pg_catalog as $$
declare v_id uuid;
begin
 if auth.uid() is null then raise exception 'authentication required'; end if;
 if length(trim(coalesce(p_requested_name,''))) not between 1 and 240 then raise exception 'invalid name'; end if;
 if length(trim(coalesce(p_email,''))) not between 3 and 320 then raise exception 'invalid email'; end if;
 if length(trim(coalesce(p_phone,''))) not between 3 and 64 then raise exception 'invalid phone'; end if;
 if p_subject_kind is not null and p_subject_kind not in ('INDIVIDUAL','COMPANY','GOVERNMENT','SECURITY_PROVIDER','DEVELOPER','PARTNER','OTHER') then raise exception 'invalid subject kind'; end if;
 insert into public.giril_onboarding_cases(applicant_user_id,requested_name,email,phone,subject_kind,country_iso2,state)
 values(auth.uid(),trim(p_requested_name),lower(trim(p_email)),trim(p_phone),p_subject_kind,nullif(upper(trim(p_country_iso2)),''),'COLLECTING')
 on conflict (applicant_user_id) where state not in ('ADMITTED','REJECTED')
 do update set requested_name=excluded.requested_name,email=excluded.email,phone=excluded.phone,subject_kind=coalesce(excluded.subject_kind,public.giril_onboarding_cases.subject_kind),country_iso2=coalesce(excluded.country_iso2,public.giril_onboarding_cases.country_iso2),state='COLLECTING',updated_at=now()
 returning id into v_id;
 return v_id;
end $$;

revoke all on function public.giril_create_onboarding_case(text,text,text,text,text) from public;
grant execute on function public.giril_create_onboarding_case(text,text,text,text,text) to authenticated;

create or replace function public.giril_record_check(p_onboarding_case_id uuid,p_check_type text,p_target_hash text,p_status text,p_source_key text,p_verifier_version text,p_verification_method text,p_metadata jsonb default '{}'::jsonb)
returns uuid language plpgsql security definer set search_path to public,pg_catalog as $$
declare v_id uuid; v_source_id uuid;
begin
 if auth.uid() is null then raise exception 'authentication required'; end if;
 if not exists(select 1 from public.giril_onboarding_cases where id=p_onboarding_case_id and applicant_user_id=auth.uid()) then raise exception 'onboarding_case_not_found'; end if;
 if p_status not in ('PENDING','RUNNING','UNAVAILABLE','ERROR','MANUAL_REVIEW') then raise exception 'server_verification_status_required'; end if;
 select id into v_source_id from public.giril_ref_sources where source_key=p_source_key and status <> 'RETIRED';
 if v_source_id is null then raise exception 'verification_source_not_registered'; end if;
 insert into public.giril_verification_checks(onboarding_case_id,check_type,target_hash,source_id,status,verifier_version,verification_method,completed_at,metadata)
 values(p_onboarding_case_id,p_check_type,p_target_hash,v_source_id,p_status,p_verifier_version,p_verification_method,case when p_status in ('UNAVAILABLE','ERROR','MANUAL_REVIEW') then now() else null end,coalesce(p_metadata,'{}'::jsonb))
 returning id into v_id;
 return v_id;
end $$;

revoke all on function public.giril_record_check(uuid,text,text,text,text,text,text,jsonb) from public;
grant execute on function public.giril_record_check(uuid,text,text,text,text,text,text,jsonb) to authenticated;

commit;