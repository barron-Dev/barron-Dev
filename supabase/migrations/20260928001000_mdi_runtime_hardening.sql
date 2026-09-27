begin;
alter table public.mdi_copilot_threads add column if not exists actor_id uuid;
alter table public.mdi_copilot_messages add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;
alter table public.mdi_copilot_messages add column if not exists tool_calls jsonb not null default '[]';
create index if not exists mdi_copilot_messages_tenant_thread_idx on public.mdi_copilot_messages(tenant_id,thread_id,created_at);
create or replace function public.mdi_rag_search(p_tenant_id uuid,p_query_embedding vector(768),p_case uuid default null,p_kinds text[] default null,p_k integer default 15)
returns table(entity_kind text,entity_id uuid,content text,similarity double precision)
language sql stable set search_path=public as $$
select e.entity_kind,e.entity_id,e.content,1-(e.vector<=>p_query_embedding) as similarity
from public.mdi_embeddings e
where e.tenant_id=p_tenant_id
  and e.vector is not null
  and (p_kinds is null or e.entity_kind=any(p_kinds))
order by e.vector<=>p_query_embedding
limit greatest(1,least(p_k,50))
$$;
commit;