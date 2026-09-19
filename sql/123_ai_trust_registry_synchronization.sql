-- 123_ai_trust_registry_synchronization.sql
create table if not exists public.ai_trust_subject_bindings(
 id uuid primary key default gen_random_uuid(),tenant_id uuid not null references public.tenants(id) on delete cascade,
 registry_kind text not null check(registry_kind in('MODEL','MODEL_VERSION','AGENT','AGENT_VERSION')),
 registry_id text not null,registry_version integer,trust_subject_id uuid not null references public.trust_subjects(id) on delete restrict,
 identity_hash text not null check(identity_hash ~ '^[0-9a-f]{64}$'),status text not null default 'ACTIVE' check(status in('ACTIVE','RETIRED')),
 created_at timestamptz not null default now(),updated_at timestamptz not null default now(),
 unique(tenant_id,registry_kind,registry_id,registry_version)
);
create index if not exists idx_ai_trust_subject_bindings_subject on public.ai_trust_subject_bindings(trust_subject_id);
alter table public.ai_trust_subject_bindings enable row level security;
revoke all on public.ai_trust_subject_bindings from public,anon,authenticated;
create or replace function public.ai_trust_identity_hash(p_doc jsonb) returns text language sql immutable set search_path=public,pg_catalog as $$ select encode(extensions.digest(convert_to(p_doc::text,'UTF8'),'sha256'),'hex') $$;
revoke all on function public.ai_trust_identity_hash(jsonb) from public,anon,authenticated;
grant execute on function public.ai_trust_identity_hash(jsonb) to service_role;

create or replace function public.ai_sync_model_trust_subject(p_tenant_id uuid,p_model_id text)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare m public.ai_models%rowtype;s public.trust_subjects%rowtype;doc jsonb;h text;
begin
 select * into m from public.ai_models where tenant_id=p_tenant_id and id=p_model_id order by version desc limit 1;
 if not found then raise exception 'ai_model_not_found'; end if;
 doc:=jsonb_build_object('registry','ai_models','model_id',m.id,'provider_model_key',m.provider_model_key,'provider_id',split_part(m.id,':',1),'version',m.version,'model_hash',m.model_hash,'artifact_hash',m.artifact_hash,'modality',m.modality,'context_limit',m.context_limit);
 h:=public.ai_trust_identity_hash(doc);
 insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,provider_id,identity_document,lifecycle_state) values(m.tenant_id,'MODEL',m.id,m.display_name,split_part(m.id,':',1),doc,case when upper(m.lifecycle_state)='ACTIVE' then 'ACTIVE' else 'SUSPENDED' end)
 on conflict(tenant_id,subject_kind,external_ref) do update set display_name=excluded.display_name,provider_id=excluded.provider_id,identity_document=excluded.identity_document,lifecycle_state=excluded.lifecycle_state,updated_at=now() returning * into s;
 insert into public.ai_trust_subject_bindings(tenant_id,registry_kind,registry_id,registry_version,trust_subject_id,identity_hash) values(m.tenant_id,'MODEL',m.id,null,s.id,h)
 on conflict(tenant_id,registry_kind,registry_id,registry_version) do update set trust_subject_id=excluded.trust_subject_id,identity_hash=excluded.identity_hash,status='ACTIVE',updated_at=now();
 insert into public.trust_subject_aliases(subject_id,alias_type,alias_value) values(s.id,'MODEL_ID',m.id) on conflict(alias_type,alias_value) do nothing;
 doc:=doc||jsonb_build_object('subject_kind','MODEL_VERSION');h:=public.ai_trust_identity_hash(doc);
 insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,provider_id,version,identity_document,lifecycle_state) values(m.tenant_id,'MODEL_VERSION',m.id||':'||m.version,m.display_name||' v'||m.version,split_part(m.id,':',1),m.version::text,doc,case when upper(m.lifecycle_state)='ACTIVE' then 'ACTIVE' else 'SUSPENDED' end)
 on conflict(tenant_id,subject_kind,external_ref) do update set identity_document=excluded.identity_document,lifecycle_state=excluded.lifecycle_state,updated_at=now() returning * into s;
 insert into public.ai_trust_subject_bindings(tenant_id,registry_kind,registry_id,registry_version,trust_subject_id,identity_hash) values(m.tenant_id,'MODEL_VERSION',m.id,m.version,s.id,h)
 on conflict(tenant_id,registry_kind,registry_id,registry_version) do update set trust_subject_id=excluded.trust_subject_id,identity_hash=excluded.identity_hash,status='ACTIVE',updated_at=now();
 insert into public.trust_subject_aliases(subject_id,alias_type,alias_value) values(s.id,'MODEL_VERSION_ID',m.id||':'||m.version) on conflict(alias_type,alias_value) do nothing;
 if m.model_hash is not null and m.model_hash ~ '^[0-9a-fA-F]{64}$' then perform public.trust_record_measurement(s.id,'WEIGHTS_HASH','SHA-256',lower(m.model_hash),'REGISTRY','ai_models',now(),null,null,jsonb_build_object('model_id',m.id,'version',m.version,'identity_hash',h)); end if;
 if m.artifact_hash is not null and m.artifact_hash ~ '^[0-9a-fA-F]{64}$' and m.artifact_hash<>m.model_hash then perform public.trust_record_measurement(s.id,'ARTIFACT_HASH','SHA-256',lower(m.artifact_hash),'REGISTRY','ai_models',now(),null,null,jsonb_build_object('model_id',m.id,'version',m.version,'identity_hash',h)); end if;
 return jsonb_build_object('model_id',m.id,'version',m.version,'model_subject_id',(select id from public.trust_subjects where tenant_id=m.tenant_id and subject_kind='MODEL' and external_ref=m.id),'model_version_subject_id',s.id,'identity_hash',h);
end$$;
revoke all on function public.ai_sync_model_trust_subject(uuid,text) from public,anon,authenticated;
grant execute on function public.ai_sync_model_trust_subject(uuid,text) to service_role;

create or replace function public.ai_sync_all_models_to_trust(p_tenant_id uuid)
returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare m record;n integer:=0;results jsonb:='[]'::jsonb;
begin for m in select distinct id from public.ai_models where tenant_id=p_tenant_id loop results:=results||jsonb_build_array(public.ai_sync_model_trust_subject(p_tenant_id,m.id));n:=n+1;end loop;return jsonb_build_object('tenant_id',p_tenant_id,'models_synced',n,'results',results);end$$;
revoke all on function public.ai_sync_all_models_to_trust(uuid) from public,anon,authenticated;
grant execute on function public.ai_sync_all_models_to_trust(uuid) to service_role;

create or replace function public.ai_trust_model_subject(p_tenant_id uuid,p_model_id text,p_model_version integer) returns uuid language sql stable security definer set search_path=public,pg_catalog as $$ select b.trust_subject_id from public.ai_trust_subject_bindings b where b.tenant_id=p_tenant_id and b.registry_kind='MODEL_VERSION' and b.registry_id=p_model_id and b.registry_version=p_model_version and b.status='ACTIVE' limit 1 $$;
revoke all on function public.ai_trust_model_subject(uuid,text,integer) from public,anon,authenticated;
grant execute on function public.ai_trust_model_subject(uuid,text,integer) to service_role;
