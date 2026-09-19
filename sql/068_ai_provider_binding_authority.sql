-- Tenant-scoped model/provider authority used by AI envelope issuance.
-- No provider credentials are stored here.

create table if not exists public.ai_provider_bindings (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    agent_id uuid not null references public.ai_agents(id) on delete cascade,
    model_id text not null,
    provider_id text not null,
    binding_hash text not null check (binding_hash ~ '^[0-9a-f]{64}$'),
    status text not null default 'active'
        check (status in ('active','revoked','expired')),
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    unique (tenant_id, agent_id, model_id, provider_id)
);

create index if not exists idx_ai_provider_bindings_lookup
    on public.ai_provider_bindings(tenant_id, agent_id, model_id, provider_id);

alter table public.ai_provider_bindings enable row level security;
revoke all on public.ai_provider_bindings from public, anon, authenticated;

create or replace function public.resolve_ai_provider_binding(
    p_tenant_id uuid,
    p_agent_id uuid,
    p_model_id text,
    p_provider_id text
) returns table (
    binding_hash text,
    status text,
    expires_at timestamptz
)
language sql
security definer
set search_path = public
as $$
    select b.binding_hash, b.status, b.expires_at
      from public.ai_provider_bindings b
     where b.tenant_id = p_tenant_id
       and b.agent_id = p_agent_id
       and b.model_id = p_model_id
       and b.provider_id = p_provider_id
       and b.status = 'active'
       and (b.expires_at is null or b.expires_at > now())
     limit 1
$$;

revoke all on function public.resolve_ai_provider_binding(uuid,uuid,text,text)
    from public, anon, authenticated;
grant execute on function public.resolve_ai_provider_binding(uuid,uuid,text,text)
    to service_role;
