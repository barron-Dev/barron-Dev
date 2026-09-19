-- 088_run_bound_execution_authority.sql
-- Server-derive every execution identity from the durable AI run.
-- Callers provide intent/risk only; they cannot substitute agent/model/provider
-- versions or policy bindings.

create or replace function public.ai_execute_run(
  p_run_id uuid,
  p_risk_level text,
  p_destructive boolean,
  p_estimated_cost_usd numeric(18,8),
  p_execution_config jsonb,
  p_approval_ref text default null,
  p_action_hash text default null,
  p_actor text default 'system',
  p_lease_seconds integer default 600,
  p_envelope_id text default null,
  p_envelope_hash text default null,
  p_envelope_expires_at timestamptz default null
) returns jsonb
language plpgsql
security definer
set search_path = public,pg_catalog
as $$
declare
  r public.ai_runs;
begin
  select * into r
    from public.ai_runs
   where id = p_run_id
   for update;

  if not found then
    raise exception 'run_not_found';
  end if;

  declare
    v_result jsonb;
    v_claimed boolean;
  begin
    v_result := public.ai_authorize_and_commit_execution(
      r.id,
      r.agent_id,
      r.mission_id,
      r.model_id,
      r.provider_id,
      r.tool_id,
      p_risk_level,
      p_destructive,
      p_estimated_cost_usd,
      p_execution_config,
      r.agent_version,
      r.mission_version,
      r.mission_hash,
      r.model_version,
      r.provider_binding_version,
      r.tool_version,
      p_approval_ref,
      r.policy_version,
      r.policy_hash,
      r.playbook_version,
      r.playbook_hash,
      r.twin_version,
      r.twin_hash,
      p_envelope_id,
      p_envelope_hash,
      left(p_actor,128),
      p_lease_seconds,
      p_action_hash
    );

    if p_envelope_id is not null then
      if p_envelope_hash is null or p_envelope_expires_at is null then
        raise exception 'envelope_replay_context_required';
      end if;
      v_claimed := public.claim_ai_execution_envelope(
        r.tenant_id,
        p_envelope_id,
        p_envelope_hash,
        p_envelope_expires_at
      );
      if not v_claimed then
        raise exception 'execution_envelope_replay_rejected';
      end if;
    end if;

    return v_result;
  end;
end;
$$;

revoke all on function public.ai_execute_run(
  uuid,text,boolean,numeric,jsonb,text,text,text,integer,text,text,timestamptz
) from public,anon,authenticated;

grant execute on function public.ai_execute_run(
  uuid,text,boolean,numeric,jsonb,text,text,text,integer,text,text
) to service_role;

comment on function public.ai_execute_run is
'Canonical run-bound execution entry point. All agent/model/provider/tool/version/policy identity is server-derived from ai_runs.';
