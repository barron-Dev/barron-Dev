-- 125_ai_trust_execution_identity_graph.sql
-- Canonical execution identity bridge: model + agent + tool + provider + runtime/environment facts.
-- No certificate/attestation is implied by registry synchronization.

alter table public.ai_execution_bindings add column if not exists runtime_id text;
alter table public.ai_execution_bindings add column if not exists runtime_version text;
alter table public.ai_execution_bindings add column if not exists runtime_hash text;
alter table public.ai_execution_bindings add column if not exists container_hash text;
alter table public.ai_execution_bindings add column if not exists dependency_hash text;
alter table public.ai_execution_bindings add column if not exists environment_hash text;
alter table public.ai_runs add column if not exists runtime_id text;
alter table public.ai_runs add column if not exists runtime_version text;
alter table public.ai_runs add column if not exists runtime_hash text;
alter table public.ai_runs add column if not exists container_hash text;
alter table public.ai_runs add column if not exists dependency_hash text;
alter table public.ai_runs add column if not exists environment_hash text;

create table if not exists public.ai_trust_execution_identities(
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete cascade,
 run_id uuid not null references public.ai_runs(id) on delete restrict, binding_id uuid references public.ai_execution_bindings(id) on delete restrict,
 model_subject_id uuid references public.trust_subjects(id) on delete restrict, agent_subject_id uuid references public.trust_subjects(id) on delete restrict,
 tool_subject_id uuid references public.trust_subjects(id) on delete restrict, provider_subject_id uuid references public.trust_subjects(id) on delete restrict,
 runtime_subject_id uuid references public.trust_subjects(id) on delete restrict,
 mission_id text not null, mission_version integer not null, mission_hash text not null,
 provider_id text not null, provider_binding_version integer not null, model_id text not null, model_version integer not null,
 agent_id uuid not null, agent_version integer not null, tool_id text, tool_version integer,
 runtime_id text, runtime_version text, runtime_hash text, container_hash text, dependency_hash text, environment_hash text,
 identity_hash text not null check(identity_hash ~ '^[0-9a-f]{64}$'), created_at timestamptz not null default now(), unique(run_id)
);
create index if not exists idx_ai_trust_execution_identity_subjects on public.ai_trust_execution_identities(tenant_id,model_subject_id,agent_subject_id,tool_subject_id,provider_subject_id,runtime_subject_id);
alter table public.ai_trust_execution_identities enable row level security;
revoke all on public.ai_trust_execution_identities from public,anon,authenticated;

create or replace function public.ai_sync_agent_trust_subject(p_tenant_id uuid,p_agent_id uuid,p_agent_version integer) returns uuid language plpgsql security definer set search_path=public,pg_catalog as $$
declare a public.ai_agents%rowtype; av public.ai_agent_versions%rowtype; s public.trust_subjects%rowtype; doc jsonb;
begin
 select * into a from public.ai_agents where tenant_id=p_tenant_id and id=p_agent_id; if not found then raise exception 'ai_agent_not_found'; end if;
 select * into av from public.ai_agent_versions where tenant_id=p_tenant_id and agent_id=p_agent_id and version=p_agent_version; if not found then raise exception 'ai_agent_version_not_found'; end if;
 doc:=jsonb_build_object('registry','ai_agents','agent_id',a.id,'name',a.name,'framework',a.framework,'model',a.model,'declared_tools',a.declared_tools,'data_scopes',a.data_scopes,'trust_level',a.trust_level,'capabilities',a.capabilities,'version',av.version,'config_hash',av.config_hash);
 insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,provider_id,identity_document,lifecycle_state) values(p_tenant_id,'AGENT',a.id::text,a.name,'cyclothone',doc,case when upper(coalesce(a.lifecycle_state,a.status)) in ('ACTIVE','ENABLED') then 'ACTIVE' else 'SUSPENDED' end)
 on conflict(tenant_id,subject_kind,external_ref) do update set display_name=excluded.display_name,identity_document=excluded.identity_document,lifecycle_state=excluded.lifecycle_state,updated_at=now() returning * into s;
 insert into public.trust_subject_aliases(subject_id,alias_type,alias_value) values(s.id,'AGENT_ID',a.id::text) on conflict(alias_type,alias_value) do nothing;
 doc:=doc||jsonb_build_object('subject_kind','AGENT_VERSION');
 insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,provider_id,version,identity_document,lifecycle_state) values(p_tenant_id,'AGENT_VERSION',a.id::text||':'||av.version,a.name||' v'||av.version,'cyclothone',av.version::text,doc,case when upper(av.state) in ('ACTIVE','ENABLED') then 'ACTIVE' else 'SUSPENDED' end)
 on conflict(tenant_id,subject_kind,external_ref) do update set identity_document=excluded.identity_document,lifecycle_state=excluded.lifecycle_state,updated_at=now() returning * into s;
 insert into public.trust_subject_aliases(subject_id,alias_type,alias_value) values(s.id,'AGENT_VERSION_ID',a.id::text||':'||av.version) on conflict(alias_type,alias_value) do nothing;
 if av.config_hash ~ '^[0-9a-fA-F]{64}$' then perform public.trust_record_measurement(s.id,'CONFIG_HASH','SHA-256',lower(av.config_hash),'REGISTRY','ai_agent_versions',now(),null,null,jsonb_build_object('agent_id',a.id,'version',av.version)); end if;
 insert into public.ai_trust_subject_bindings(tenant_id,registry_kind,registry_id,registry_version,trust_subject_id,identity_hash) values(p_tenant_id,'AGENT',a.id::text,null,(select id from public.trust_subjects where tenant_id=p_tenant_id and subject_kind='AGENT' and external_ref=a.id::text),public.ai_trust_identity_hash(doc))
 on conflict(tenant_id,registry_kind,registry_id,registry_version) do update set trust_subject_id=excluded.trust_subject_id,identity_hash=excluded.identity_hash,status='ACTIVE',updated_at=now();
 insert into public.ai_trust_subject_bindings(tenant_id,registry_kind,registry_id,registry_version,trust_subject_id,identity_hash) values(p_tenant_id,'AGENT_VERSION',a.id::text,av.version,s.id,public.ai_trust_identity_hash(doc))
 on conflict(tenant_id,registry_kind,registry_id,registry_version) do update set trust_subject_id=excluded.trust_subject_id,identity_hash=excluded.identity_hash,status='ACTIVE',updated_at=now();
 return s.id;
end$$;

create or replace function public.ai_sync_tool_trust_subject(p_tenant_id uuid,p_tool_id text,p_tool_version integer) returns uuid language plpgsql security definer set search_path=public,pg_catalog as $$
declare t public.ai_tools%rowtype; s public.trust_subjects%rowtype; doc jsonb;
begin
 select * into t from public.ai_tools where id=p_tool_id and (tenant_id=p_tenant_id or tenant_id is null) and version=p_tool_version; if not found then raise exception 'ai_tool_not_found'; end if;
 doc:=jsonb_build_object('registry','ai_tools','tool_id',t.id,'tool_key',t.tool_key,'version',t.version,'schema_hash',t.schema_hash,'risk_level',t.risk_level);
 insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,provider_id,version,identity_document,lifecycle_state) values(p_tenant_id,'TOOL',t.id,t.tool_key,'cyclothone',t.version::text,doc,case when upper(t.lifecycle_state) in ('ACTIVE','ENABLED') then 'ACTIVE' else 'SUSPENDED' end)
 on conflict(tenant_id,subject_kind,external_ref) do update set identity_document=excluded.identity_document,lifecycle_state=excluded.lifecycle_state,updated_at=now() returning * into s;
 insert into public.trust_subject_aliases(subject_id,alias_type,alias_value) values(s.id,'TOOL_ID',t.id||':'||t.version) on conflict(alias_type,alias_value) do nothing;
 if t.schema_hash ~ '^[0-9a-fA-F]{64}$' then perform public.trust_record_measurement(s.id,'CONFIG_HASH','SHA-256',lower(t.schema_hash),'REGISTRY','ai_tools',now(),null,null,jsonb_build_object('tool_id',t.id,'version',t.version,'risk_level',t.risk_level)); end if;
 return s.id;
end$$;

create or replace function public.ai_sync_provider_trust_subject(p_tenant_id uuid,p_provider_id text,p_binding_version integer) returns uuid language plpgsql security definer set search_path=public,pg_catalog as $$
declare p public.ai_providers%rowtype; s public.trust_subjects%rowtype; b public.ai_provider_bindings%rowtype; doc jsonb; ref text;
begin
 select * into p from public.ai_providers where id=p_provider_id and (tenant_id=p_tenant_id or tenant_id is null) limit 1; if not found then raise exception 'ai_provider_not_found'; end if;
 select * into b from public.ai_provider_bindings where tenant_id=p_tenant_id and provider_id=p_provider_id and status='ACTIVE' order by created_at desc limit 1;
 ref:=p_provider_id||':'||p_binding_version; doc:=jsonb_build_object('registry','ai_provider_bindings','provider_id',p_provider_id,'provider_binding_version',p_binding_version,'provider_key',p.provider_key,'binding_hash',case when b.id is null then null else b.binding_hash end);
 insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,provider_id,version,identity_document,lifecycle_state) values(p_tenant_id,'ENVIRONMENT',ref,p.display_name,p_provider_id,p_binding_version::text,doc,case when upper(p.lifecycle_state) in ('ACTIVE','ENABLED') then 'ACTIVE' else 'SUSPENDED' end)
 on conflict(tenant_id,subject_kind,external_ref) do update set identity_document=excluded.identity_document,lifecycle_state=excluded.lifecycle_state,updated_at=now() returning * into s;
 insert into public.trust_subject_aliases(subject_id,alias_type,alias_value) values(s.id,'PROVIDER_BINDING',ref) on conflict(alias_type,alias_value) do nothing;
 if b.binding_hash ~ '^[0-9a-fA-F]{64}$' then perform public.trust_record_measurement(s.id,'CONFIG_HASH','SHA-256',lower(b.binding_hash),'REGISTRY','ai_provider_bindings',now(),null,null,jsonb_build_object('provider_id',p_provider_id,'provider_binding_version',p_binding_version)); end if;
 return s.id;
end$$;

create or replace function public.ai_sync_execution_trust_identity(p_run_id uuid) returns jsonb language plpgsql security definer set search_path=public,pg_catalog as $$
declare r public.ai_runs%rowtype; b public.ai_execution_bindings%rowtype; model_id uuid; agent_id uuid; tool_id uuid; provider_id uuid; runtime_id uuid; doc jsonb; h text; out_id uuid;
begin
 select * into r from public.ai_runs where id=p_run_id; if not found then raise exception 'run_not_found'; end if;
 select * into b from public.ai_execution_bindings where tenant_id=r.tenant_id and mission_id=r.mission_id and mission_version=r.mission_version and mission_hash=r.mission_hash and agent_id=r.agent_id and agent_version=r.agent_version and model_id=r.model_id and model_version=r.model_version and provider_id=r.provider_id and provider_binding_version=r.provider_binding_version and coalesce(tool_id,'')=coalesce(r.tool_id,'') and coalesce(tool_version,-1)=coalesce(r.tool_version,-1) and status='ACTIVE' order by created_at desc limit 1;
 model_id:=public.ai_trust_model_subject(r.tenant_id,r.model_id,r.model_version);
 agent_id:=public.ai_sync_agent_trust_subject(r.tenant_id,r.agent_id,r.agent_version);
 if r.tool_id is not null and r.tool_version is not null then tool_id:=public.ai_sync_tool_trust_subject(r.tenant_id,r.tool_id,r.tool_version); end if;
 provider_id:=public.ai_sync_provider_trust_subject(r.tenant_id,r.provider_id,r.provider_binding_version);
 if r.runtime_id is not null then
  doc:=jsonb_build_object('source','ai_runs','runtime_id',r.runtime_id,'runtime_version',r.runtime_version,'runtime_hash',r.runtime_hash,'container_hash',r.container_hash,'dependency_hash',r.dependency_hash,'environment_hash',r.environment_hash);
  insert into public.trust_subjects(tenant_id,subject_kind,external_ref,display_name,version,identity_document,lifecycle_state) values(r.tenant_id,'RUNTIME',r.runtime_id,coalesce(r.runtime_id,'runtime'),r.runtime_version,doc,'ACTIVE')
  on conflict(tenant_id,subject_kind,external_ref) do update set identity_document=excluded.identity_document,version=excluded.version,updated_at=now() returning id into runtime_id;
  if r.runtime_hash ~ '^[0-9a-fA-F]{64}$' then perform public.trust_record_measurement(runtime_id,'RUNTIME_HASH','SHA-256',lower(r.runtime_hash),'REGISTRY','ai_runs',now(),null,null,jsonb_build_object('run_id',r.id)); end if;
 end if;
 doc:=jsonb_build_object('tenant_id',r.tenant_id,'run_id',r.id,'mission_id',r.mission_id,'mission_version',r.mission_version,'mission_hash',r.mission_hash,'model_subject_id',model_id,'agent_subject_id',agent_id,'tool_subject_id',tool_id,'provider_subject_id',provider_id,'runtime_subject_id',runtime_id,'model_id',r.model_id,'model_version',r.model_version,'agent_id',r.agent_id,'agent_version',r.agent_version,'provider_id',r.provider_id,'provider_binding_version',r.provider_binding_version,'tool_id',r.tool_id,'tool_version',r.tool_version,'runtime_id',r.runtime_id,'runtime_version',r.runtime_version,'runtime_hash',r.runtime_hash,'container_hash',r.container_hash,'dependency_hash',r.dependency_hash,'environment_hash',r.environment_hash,'policy_version',r.policy_version,'policy_hash',r.policy_hash,'playbook_version',r.playbook_version,'playbook_hash',r.playbook_hash,'twin_version',r.twin_version,'twin_hash',r.twin_hash,'envelope_version',r.envelope_version,'envelope_hash',r.envelope_hash);
 h:=public.ai_trust_identity_hash(doc);
 insert into public.ai_trust_execution_identities(tenant_id,run_id,binding_id,model_subject_id,agent_subject_id,tool_subject_id,provider_subject_id,runtime_subject_id,mission_id,mission_version,mission_hash,provider_id,provider_binding_version,model_id,model_version,agent_id,agent_version,tool_id,tool_version,runtime_id,runtime_version,runtime_hash,container_hash,dependency_hash,environment_hash,identity_hash)
 values(r.tenant_id,r.id,b.id,model_id,agent_id,tool_id,provider_id,runtime_id,r.mission_id,r.mission_version,r.mission_hash,r.provider_id,r.provider_binding_version,r.model_id,r.model_version,r.agent_id,r.agent_version,r.tool_id,r.tool_version,r.runtime_id,r.runtime_version,r.runtime_hash,r.container_hash,r.dependency_hash,r.environment_hash,h)
 on conflict(run_id) do update set binding_id=excluded.binding_id,model_subject_id=excluded.model_subject_id,agent_subject_id=excluded.agent_subject_id,tool_subject_id=excluded.tool_subject_id,provider_subject_id=excluded.provider_subject_id,runtime_subject_id=excluded.runtime_subject_id,identity_hash=excluded.identity_hash,created_at=now()
 returning id into out_id;
 return jsonb_build_object('execution_identity_id',out_id,'identity_hash',h,'model_subject_id',model_id,'agent_subject_id',agent_id,'tool_subject_id',tool_id,'provider_subject_id',provider_id,'runtime_subject_id',runtime_id);
end$$;

revoke all on function public.ai_sync_agent_trust_subject(uuid,uuid,integer) from public,anon,authenticated;
revoke all on function public.ai_sync_tool_trust_subject(uuid,text,integer) from public,anon,authenticated;
revoke all on function public.ai_sync_provider_trust_subject(uuid,text,integer) from public,anon,authenticated;
revoke all on function public.ai_sync_execution_trust_identity(uuid) from public,anon,authenticated;
grant execute on function public.ai_sync_agent_trust_subject(uuid,uuid,integer) to service_role;
grant execute on function public.ai_sync_tool_trust_subject(uuid,text,integer) to service_role;
grant execute on function public.ai_sync_provider_trust_subject(uuid,text,integer) to service_role;
grant execute on function public.ai_sync_execution_trust_identity(uuid) to service_role;