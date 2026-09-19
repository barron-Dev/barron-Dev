-- Bind AI execution authority to the existing case_actions -> commands response chain.
-- Replay state is a ledger only; case_actions and commands remain the durable response authorities.

alter table public.case_actions
    add column if not exists ai_agent_id uuid references public.ai_agents(id) on delete set null,
    add column if not exists ai_model_id text,
    add column if not exists ai_provider_id text,
    add column if not exists ai_tool_name text,
    add column if not exists ai_target text,
    add column if not exists ai_envelope_id text,
    add column if not exists ai_envelope_hash text,
    add column if not exists ai_args_hash text;

create index if not exists idx_case_actions_ai_envelope
    on public.case_actions(tenant_id, ai_envelope_id)
    where ai_envelope_id is not null;

alter table public.commands
    add column if not exists case_action_id uuid references public.case_actions(id) on delete set null,
    add column if not exists ai_agent_id uuid references public.ai_agents(id) on delete set null,
    add column if not exists ai_model_id text,
    add column if not exists ai_provider_id text,
    add column if not exists ai_tool_name text,
    add column if not exists ai_target text,
    add column if not exists ai_envelope_id text,
    add column if not exists ai_envelope_hash text,
    add column if not exists ai_args_hash text;

create index if not exists idx_commands_case_action on public.commands(case_action_id);
create index if not exists idx_commands_ai_envelope
    on public.commands(tenant_id, ai_envelope_id)
    where ai_envelope_id is not null;

create table if not exists public.ai_execution_replay (
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    envelope_id text not null,
    envelope_hash text not null,
    expires_at timestamptz not null,
    claimed_at timestamptz not null default now(),
    primary key (tenant_id, envelope_id)
);
create index if not exists idx_ai_execution_replay_expiry
    on public.ai_execution_replay(expires_at);
alter table public.ai_execution_replay enable row level security;

revoke all on public.ai_execution_replay from public, anon, authenticated;

create or replace function public.claim_ai_execution_envelope(
    p_tenant_id uuid,
    p_envelope_id text,
    p_envelope_hash text,
    p_expires_at timestamptz
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_tenant_id is null
       or p_envelope_id is null
       or length(p_envelope_id) = 0
       or length(p_envelope_id) > 128
       or p_envelope_hash is null
       or length(p_envelope_hash) <> 64
       or p_expires_at <= now() then
        return false;
    end if;

    insert into public.ai_execution_replay(
        tenant_id, envelope_id, envelope_hash, expires_at
    )
    values (
        p_tenant_id, p_envelope_id, p_envelope_hash, p_expires_at
    )
    on conflict (tenant_id, envelope_id) do nothing;

    return found;
end;
$$;

revoke all on function public.claim_ai_execution_envelope(uuid,text,text,timestamptz)
    from public, anon, authenticated;
grant execute on function public.claim_ai_execution_envelope(uuid,text,text,timestamptz)
    to service_role;
