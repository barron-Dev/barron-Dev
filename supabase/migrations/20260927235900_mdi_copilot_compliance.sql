begin;

create extension if not exists vector;

create table if not exists public.mdi_subject_tenants (tenant_id uuid not null references public.tenants(id) on delete cascade, subject_id uuid not null references public.mdi_subjects(id) on delete cascade, created_at timestamptz not null default now(), primary key(tenant_id,subject_id));
alter table public.mdi_subject_tenants enable row level security;
create index if not exists mdi_subject_tenants_subject on public.mdi_subject_tenants(subject_id);
revoke all on public.mdi_subject_tenants from anon,authenticated;

drop policy if exists mdi_subject_tenants_service_role on public.mdi_subject_tenants;
create policy mdi_subject_tenants_service_role on public.mdi_subject_tenants for all to service_role using(true) with check(true);

create table if not exists public.mdi_embeddings (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  entity_kind text not null check (entity_kind in ('subject','edge','case','sar','threat','payment','attribution')),
  entity_id uuid not null,
  content text not null,
  content_hash text not null,
  embedding vector(768),
  model text not null default 'nomic-embed-text',
  updated_at timestamptz not null default now(),
  unique (tenant_id, entity_kind, entity_id, model)
);
alter table public.mdi_embeddings enable row level security;
create index if not exists mdi_embeddings_hnsw on public.mdi_embeddings using hnsw (embedding vector_cosine_ops) with (m=16,ef_construction=64);
create index if not exists mdi_embeddings_tenant_kind on public.mdi_embeddings (tenant_id,entity_kind);

create table if not exists public.mdi_copilot_threads (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  case_id uuid,
  actor_id uuid not null,
  title text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.mdi_copilot_threads enable row level security;
create index if not exists mdi_copilot_threads_tenant on public.mdi_copilot_threads(tenant_id,updated_at desc);

create table if not exists public.mdi_copilot_messages (
  id bigserial primary key,
  tenant_id uuid not null,
  thread_id uuid not null references public.mdi_copilot_threads(id) on delete cascade,
  role text not null check (role in ('user','assistant','tool','system')),
  content text not null,
  tool_calls jsonb not null default '[]'::jsonb,
  citations jsonb not null default '[]'::jsonb,
  tokens_in int,
  tokens_out int,
  created_at timestamptz not null default now()
);
alter table public.mdi_copilot_messages enable row level security;
create index if not exists mdi_copilot_messages_tenant_thread on public.mdi_copilot_messages(tenant_id,thread_id,created_at desc);

create table if not exists public.mdi_compliance_rules (
  id uuid primary key default gen_random_uuid(),
  jurisdiction text not null check (jurisdiction in ('GDPR','UAE_PDPL','SAUDI_PDPL','POPIA','DPDP_IN')),
  statute text not null,
  requirement text not null,
  applies_to text[] not null default '{}',
  data_category text[] not null default '{}',
  retention_days int,
  lawful_bases text[] not null default '{}',
  cross_border text check (cross_border in ('allowed','conditional','prohibited')),
  dpo_required boolean not null default false,
  audit_evidence text[] not null default '{}',
  source_url text,
  source_version text,
  created_at timestamptz not null default now(),
  unique(jurisdiction,statute,requirement)
);
alter table public.mdi_compliance_rules enable row level security;

insert into public.mdi_compliance_rules
(jurisdiction,statute,requirement,applies_to,data_category,retention_days,lawful_bases,cross_border,dpo_required,audit_evidence,source_url)
values
('GDPR','Art. 5(1)(e)','Storage limitation',array['msisdn','imei','imsi','ip','email'],array['pii','location'],365,array['consent','contract','legal_obligation','vital_interest','public_task','legitimate_interest'],'conditional',true,array['retention_policy','deletion_log'],'https://eur-lex.europa.eu/eli/reg/2016/679/art_5/oj'),
('GDPR','Art. 6','Lawful basis for processing',array['msisdn','imei','imsi','ip','email','person'],array['pii'],null,array['consent','contract','legal_obligation','vital_interest','public_task','legitimate_interest'],'conditional',true,array['consent_record','dpa_reference'],'https://eur-lex.europa.eu/eli/reg/2016/679/art_6/oj'),
('GDPR','Art. 33','Breach notification',array[]::text[],array['pii','location'],null,array['legal_obligation'],'allowed',true,array['incident_report','notification_log'],'https://eur-lex.europa.eu/eli/reg/2016/679/art_33/oj'),
('UAE_PDPL','Federal Decree-Law No. 45 of 2021','Personal data processing principles and lawful processing',array['msisdn','imei','imsi','person'],array['pii','sensitive'],null,array['consent','legal_obligation','public_interest'],'conditional',false,array['consent_record','purpose_register'],'https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws'),
('SAUDI_PDPL','Personal Data Protection Law','Purpose limitation and lawful processing',array['msisdn','imei','person'],array['pii'],365,array['consent','contract','legal_obligation'],'conditional',false,array['purpose_register','processing_record'],'https://sdaia.gov.sa/en/SDAIA/about/Pages/PDPL.aspx'),
('POPIA','Section 19','Security safeguards',array['msisdn','imei','imsi','person'],array['pii','location'],null,array['consent','legal_obligation','legitimate_interest'],'conditional',false,array['encryption_evidence','access_log'],'https://www.gov.za/documents/protection-personal-information-act'),
('POPIA','Section 72','Transborder information flows',array['msisdn','person'],array['pii'],null,array['consent','legal_obligation'],'conditional',false,array['adequacy_check','transfer_record'],'https://www.gov.za/documents/protection-personal-information-act'),
('DPDP_IN','Section 5','Notice',array['msisdn','person'],array['pii'],null,array['consent'],'conditional',false,array['notice_version','consent_record'],'https://www.meity.gov.in/data-protection-framework'),
('DPDP_IN','Section 13','Rights of Data Principal',array['msisdn','person'],array['pii'],null,array['legal_obligation'],'conditional',false,array['dsar_log','grievance_log'],'https://www.meity.gov.in/data-protection-framework')
on conflict(jurisdiction,statute,requirement) do nothing;

create table if not exists public.mdi_compliance_findings (
  id bigserial primary key,
  tenant_id uuid not null,
  jurisdiction text not null,
  rule_id uuid references public.mdi_compliance_rules(id),
  case_id uuid,
  subject_id uuid,
  severity text not null check (severity in ('info','warning','violation','critical')),
  finding text not null,
  evidence jsonb not null default '{}',
  remediated_at timestamptz,
  detected_at timestamptz not null default now()
);
alter table public.mdi_compliance_findings enable row level security;
create index if not exists mdi_compliance_findings_tenant_time on public.mdi_compliance_findings(tenant_id,detected_at desc);

create table if not exists public.mdi_lawful_basis_log (
  id bigserial primary key,
  tenant_id uuid not null,
  actor_id uuid,
  action text not null,
  subject_id uuid,
  case_id uuid,
  jurisdiction text not null,
  lawful_basis text not null,
  legal_ref text,
  purpose text not null,
  occurred_at timestamptz not null default now(),
  expires_at timestamptz
);
alter table public.mdi_lawful_basis_log enable row level security;
create index if not exists mdi_lb_tenant_subject on public.mdi_lawful_basis_log(tenant_id,subject_id,occurred_at desc);

create table if not exists public.mdi_dsar_requests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  subject_hash text not null,
  jurisdiction text not null,
  request_type text not null check (request_type in ('access','correct','erase','port','restrict')),
  status text not null default 'received' check (status in ('received','verifying','fulfilling','completed','refused')),
  received_at timestamptz not null default now(),
  sla_deadline timestamptz not null,
  completed_at timestamptz,
  response_ref text,
  created_by uuid
);
alter table public.mdi_dsar_requests enable row level security;
create index if not exists mdi_dsar_tenant_sla on public.mdi_dsar_requests(tenant_id,status,sla_deadline);

create or replace function public.mdi_rag_search(
  p_tenant_id uuid,
  p_query_embedding vector(768),
  p_case uuid default null,
  p_kinds text[] default null,
  p_k int default 20
) returns table(entity_kind text,entity_id uuid,content text,vec_sim numeric,graph_boost numeric,final_score numeric)
language sql stable
security invoker
set search_path=public,extensions
as $$
with vec as (
  select e.entity_kind,e.entity_id,e.content,
         1-(e.embedding <=> p_query_embedding) as sim
  from public.mdi_embeddings e
  where e.tenant_id=p_tenant_id
    and exists (select 1 from public.mdi_subject_tenants st where st.tenant_id=p_tenant_id and st.subject_id=e.entity_id)
    and e.embedding is not null
    and (p_kinds is null or e.entity_kind=any(p_kinds))
  order by e.embedding <=> p_query_embedding
  limit greatest(p_k,1)*3
),
case_ctx as (
  select subject_id from public.mdi_case_links where case_id=p_case
)
select v.entity_kind,v.entity_id,v.content,
       v.sim::numeric,
       case when exists(select 1 from public.mdi_subject_tenants st where st.tenant_id=p_tenant_id and st.subject_id=v.entity_id) then least(coalesce((select count(*) from public.mdi_graph_edges e where e.src_id=v.entity_id or e.dst_id=v.entity_id),0)::numeric/20,1) else 0 end,
       (v.sim*0.75
        +case when exists(select 1 from public.mdi_subject_tenants st where st.tenant_id=p_tenant_id and st.subject_id=v.entity_id) then least(coalesce((select count(*) from public.mdi_graph_edges e where e.src_id=v.entity_id or e.dst_id=v.entity_id),0)::numeric/20,1)*0.15 else 0 end
        +case when p_case is not null and v.entity_id in(select subject_id from case_ctx) then 0.10 else 0 end)::numeric
from vec v order by 6 desc limit greatest(p_k,1);
$$;
revoke all on function public.mdi_rag_search(uuid,vector,uuid,text[],int) from public,anon,authenticated;
grant execute on function public.mdi_rag_search(uuid,vector,uuid,text[],int) to service_role;

create or replace function public.mdi_audit_retention(p_tenant_id uuid)
returns table(jurisdiction text,subject_id uuid,age_days int,rule_statute text,severity text)
language sql stable security invoker set search_path=public,extensions as $$
select r.jurisdiction,s.id,extract(day from now()-s.first_seen)::int,r.statute,
case when extract(day from now()-s.first_seen)>r.retention_days*1.5 then 'critical' else 'violation' end
from public.mdi_subjects s join public.mdi_subject_tenants st on st.subject_id=s.id and st.tenant_id=p_tenant_id join public.mdi_compliance_rules r on s.kind::text=any(r.applies_to)
where s.id=st.subject_id and r.retention_days is not null
and extract(day from now()-s.first_seen)>r.retention_days
and not exists(select 1 from public.mdi_lawful_basis_log l where l.tenant_id=p_tenant_id and l.subject_id=s.id and (l.expires_at is null or l.expires_at>now()));
$$;
revoke all on function public.mdi_audit_retention(uuid) from public,anon,authenticated;
grant execute on function public.mdi_audit_retention(uuid) to service_role;

create or replace function public.mdi_audit_lawful_basis(p_tenant_id uuid)
returns table(subject_id uuid,action text,days_since int,severity text)
language sql stable security invoker set search_path=public,extensions as $$
select o.subject_id,o.capability::text,extract(day from now()-o.called_at)::int,'violation'
from public.mdi_provider_calls o join public.mdi_subject_tenants st on st.subject_id=o.subject_id and st.tenant_id=p_tenant_id
where o.subject_id=st.subject_id and o.subject_id is not null and o.ok
and not exists(select 1 from public.mdi_lawful_basis_log l where l.tenant_id=p_tenant_id and l.subject_id=o.subject_id and l.action like '%'||o.capability::text||'%' and l.occurred_at<=o.called_at)
and o.called_at>now()-interval '30 days';
$$;
revoke all on function public.mdi_audit_lawful_basis(uuid) from public,anon,authenticated;
grant execute on function public.mdi_audit_lawful_basis(uuid) to service_role;

create or replace function public.mdi_audit_cross_border(p_tenant_id uuid)
returns table(subject_id uuid,from_jurisdiction text,to_jurisdiction text,severity text,rule_statute text)
language sql stable security invoker set search_path=public,extensions as $$
select o.subject_id,coalesce(s.country_iso2,'XX'),coalesce(p.coverage->>'countries','UNKNOWN'),
case when r.cross_border='prohibited' then 'critical' else 'warning' end,r.statute
from public.mdi_provider_calls o
join public.mdi_subjects s on s.id=o.subject_id join public.mdi_subject_tenants st on st.subject_id=s.id and st.tenant_id=p_tenant_id
join public.mdi_providers p on p.id=o.provider_id
join public.mdi_compliance_rules r on r.jurisdiction=case s.country_iso2 when 'SA' then 'SAUDI_PDPL' when 'AE' then 'UAE_PDPL' else r.jurisdiction end
where st.tenant_id=p_tenant_id and r.cross_border='prohibited' and o.called_at>now()-interval '30 days';
$$;
revoke all on function public.mdi_audit_cross_border(uuid) from public,anon,authenticated;
grant execute on function public.mdi_audit_cross_border(uuid) to service_role;

create or replace function public.mdi_dsar_sla_breach(p_tenant_id uuid)
returns table(dsar_id uuid,jurisdiction text,days_overdue int,severity text)
language sql stable security invoker set search_path=public,extensions as $$
select id,jurisdiction,greatest(extract(day from now()-sla_deadline)::int,0),
case when now()>sla_deadline+interval '15 days' then 'critical' when now()>sla_deadline then 'violation' else 'warning' end
from public.mdi_dsar_requests where tenant_id=p_tenant_id and status not in('completed','refused') and now()>sla_deadline-interval '5 days';
$$;
revoke all on function public.mdi_dsar_sla_breach(uuid) from public,anon,authenticated;
grant execute on function public.mdi_dsar_sla_breach(uuid) to service_role;

create or replace function public.mdi_dsar_sla(p_jurisdiction text)
returns interval language sql immutable as $$
select interval '30 days';
$$;
revoke all on function public.mdi_dsar_sla(text) from public,anon,authenticated;
grant execute on function public.mdi_dsar_sla(text) to service_role;

commit;
