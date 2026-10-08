begin;

create or replace function public.mdi_bind_subject_tenant(
  p_tenant_id uuid,
  p_kind public.mdi_subject_kind,
  p_canonical text,
  p_display text default null,
  p_country char default null,
  p_attrs jsonb default '{}'::jsonb,
  p_pii smallint default 0
) returns uuid
language plpgsql security invoker set search_path=''
as $$
declare v_subject_id uuid;
begin
  if p_tenant_id is null then raise exception 'mdi_subject_tenant_required'; end if;
  if p_canonical is null or btrim(p_canonical)='' then raise exception 'mdi_subject_canonical_required'; end if;
  v_subject_id := public.mdi_upsert_subject(p_kind,p_canonical,p_display,p_country,coalesce(p_attrs,'{}'::jsonb),p_pii);
  insert into public.mdi_subject_tenants(tenant_id,subject_id) values(p_tenant_id,v_subject_id)
  on conflict (tenant_id,subject_id) do nothing;
  return v_subject_id;
end $$;
revoke execute on function public.mdi_bind_subject_tenant(uuid,public.mdi_subject_kind,text,text,char,jsonb,smallint) from public,anon,authenticated;
grant execute on function public.mdi_bind_subject_tenant(uuid,public.mdi_subject_kind,text,text,char,jsonb,smallint) to service_role;
commit;