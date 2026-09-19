-- 086_canonical_execution_commit_atomicity.sql
-- Harden the canonical execution boundary:
-- admission identity is durably fingerprinted and destructive approvals are
-- consumed only inside the same transaction as exact execution commit.

create or replace function public.ai_execution_admission_hash(
  p_run_id uuid
) returns text
language sql
stable
security definer
set search_path = public,pg_catalog
as $$
  select encode(
    digest(
      convert_to(
        coalesce(
          (
            select jsonb_build_object(
              'run_id', p_run_id,
              'leases',
                coalesce(
                  (
                    select jsonb_agg(
                      jsonb_build_object(
                        'id', l.id,
                        'scope', l.scope,
                        'scope_id', l.scope_id,
                        'granted_at', l.granted_at,
                        'expires_at', l.expires_at
                      )
                      order by l.scope, l.scope_id, l.id
                    )
                    from public.ai_admission_leases l
                    where l.run_id = p_run_id
                      and l.released_at is null
                  ),
                  '[]'::jsonb
                ),
              'reservations',
                coalesce(
                  (
                    select jsonb_agg(
                      jsonb_build_object(
                        'id', r.id,
                        'budget_id', r.budget_id,
                        'amount_usd', r.amount_usd,
                        'state', r.state
                      )
                      order by r.budget_id, r.id
                    )
                    from public.ai_budget_reservations r
                    where r.run_id = p_run_id
                      and r.state = 'RESERVED'
                  ),
                  '[]'::jsonb
                )
            )
          ),
          jsonb_build_object('run_id', p_run_id, 'leases', '[]'::jsonb, 'reservations', '[]'::jsonb)
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
$$;

revoke all on function public.ai_execution_admission_hash(uuid)
  from public,anon,authenticated;
grant execute on function public.ai_execution_admission_hash(uuid)
  to service_role;

create or replace function public.ai_authorize_and_commit_execution(
  p_run_id uuid,
  p_agent_id uuid,
  p_mission_id text,
  p_model_id text,
  p_provider_id text,
  p_tool_id text,
  p_risk_level text,
  p_destructive boolean,
  p_estimated_cost_usd numeric(18,8),
  p_execution_config jsonb,
  p_agent_version integer,
  p_mission_version integer,
  p_mission_hash text,
  p_model_version integer,
  p_provider_binding_version integer,
  p_tool_version integer,
  p_approval_ref text default null,
  p_policy_version text default null,
  p_policy_hash text default null,
  p_playbook_version text default null,
  p_playbook_hash text default null,
  p_twin_version text default null,
  p_twin_hash text default null,
  p_envelope_id text default null,
  p_envelope_hash text default null,
  p_actor text default 'system',
  p_lease_seconds integer default 600,
  p_action_hash text default null
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  v_auth jsonb;
  v_commit jsonb;
  v_admission_hash text;
begin
  if p_execution_config is null then
    raise exception 'execution_config_required';
  end if;

  v_auth := public.ai_authorize_execution(
    p_run_id,
    p_agent_id,
    p_mission_id,
    p_model_id,
    p_provider_id,
    p_tool_id,
    p_risk_level,
    p_destructive,
    p_estimated_cost_usd,
    p_approval_ref,
    p_policy_version,
    p_policy_hash,
    p_actor,
    p_lease_seconds,
    p_action_hash
  );

  if coalesce((v_auth->>'allowed')::boolean,false) is not true then
    return v_auth;
  end if;

  v_admission_hash := public.ai_execution_admission_hash(p_run_id);

  v_commit := public.ai_execution_commit(
    p_run_id,
    (v_auth->>'decision_id')::bigint,
    p_execution_config,
    p_agent_version,
    p_mission_id,
    p_mission_version,
    p_mission_hash,
    p_model_id,
    p_model_version,
    p_provider_id,
    p_provider_binding_version,
    p_tool_id,
    p_tool_version,
    p_policy_version,
    p_policy_hash,
    p_playbook_version,
    p_playbook_hash,
    p_twin_version,
    p_twin_hash,
    p_envelope_id,
    p_envelope_hash,
    v_admission_hash
  );

  -- For destructive execution the approval is consumed only after the exact
  -- execution provenance has committed. Any later exception rolls the whole
  -- database transaction back, including the provenance and consumption.
  if p_destructive then
    if p_approval_ref is null or p_action_hash is null then
      raise exception 'destructive_execution_approval_context_required';
    end if;

    perform public.ai_consume_execution_approval(
      p_run_id,
      p_approval_ref,
      p_action_hash,
      p_risk_level
    );
  end if;

  return v_commit || jsonb_build_object(
    'allowed',true,
    'decision','ALLOW',
    'decision_id',v_auth->>'decision_id',
    'decision_hash',v_auth->>'decision_hash',
    'admission_hash',v_admission_hash
  );
end;
$$;

revoke all on function public.ai_authorize_and_commit_execution(
  uuid,uuid,text,text,text,text,text,boolean,numeric,jsonb,integer,integer,text,integer,integer,integer,
  text,text,text,text,text,text,text,text,text,integer,text
) from public,anon,authenticated;
grant execute on function public.ai_authorize_and_commit_execution(
  uuid,uuid,text,text,text,text,text,boolean,numeric,jsonb,integer,integer,text,integer,integer,integer,
  text,text,text,text,text,text,text,text,integer,text
) to service_role;

comment on function public.ai_authorize_and_commit_execution is
'Canonical atomic execution boundary: security admission, resource admission, exact provenance commit, and destructive approval consumption occur in one transaction.';

-- Bind response actions to the same canonical AI run used for execution.
alter table public.case_actions
  add column if not exists ai_run_id uuid references public.ai_runs(id) on delete restrict;

create index if not exists idx_case_actions_ai_run
  on public.case_actions(tenant_id, ai_run_id)
  where ai_run_id is not null;

alter table public.commands
  add column if not exists ai_run_id uuid references public.ai_runs(id) on delete restrict;

create index if not exists idx_commands_ai_run
  on public.commands(tenant_id, ai_run_id)
  where ai_run_id is not null;

comment on column public.case_actions.ai_run_id is
'Canonical AI execution run bound to this response action; response dispatch must not invent a parallel execution identity.';

comment on column public.commands.ai_run_id is
'Canonical AI execution run inherited from the response case action.';
