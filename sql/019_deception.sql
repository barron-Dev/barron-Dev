-- Sentinel Deception Layer, migration 019.
-- Defensive deception artifacts are tenant-scoped and deliberately inert.
-- Canary callbacks retain security telemetry, not the contents of accessed files.

create table if not exists deception_artifacts (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    artifact_type text not null check (artifact_type in ('canary_token','honeyfile','fake_aws_key','fake_browser_cookie','fake_ssh_key','fake_wallet_seed','fake_admin_share','fake_service_account')),
    name text not null,
    target text not null,
    token_prefix text not null,
    token_hash text not null,
    metadata jsonb not null default '{}'::jsonb,
    severity text not null default 'critical' check (severity in ('medium','high','critical')),
    enabled boolean not null default true,
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    last_triggered_at timestamptz,
    trigger_count bigint not null default 0 check (trigger_count >= 0),
    unique (tenant_id, token_hash)
);
create index if not exists idx_deception_artifacts_lookup on deception_artifacts(token_hash) where enabled = true;
create index if not exists idx_deception_artifacts_tenant on deception_artifacts(tenant_id, artifact_type, enabled);
alter table deception_artifacts enable row level security;
create policy deception_artifacts_tenant_select on deception_artifacts for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));
create policy deception_artifacts_tenant_insert on deception_artifacts for insert to authenticated
    with check (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

create table if not exists deception_triggers (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    artifact_id uuid not null references deception_artifacts(id) on delete cascade,
    observed_at timestamptz not null default now(),
    source_ip inet,
    forwarded_for text,
    user_agent text,
    request_method text,
    request_path text,
    source_country text,
    source_asn bigint,
    source_org text,
    evidence jsonb not null default '{}'::jsonb,
    alert_severity text not null default 'critical' check (alert_severity in ('high','critical')),
    case_status text not null default 'pending' check (case_status in ('pending','created','failed','suppressed')),
    case_id uuid,
    created_at timestamptz not null default now()
);
create index if not exists idx_deception_triggers_tenant_time on deception_triggers(tenant_id, observed_at desc);
create index if not exists idx_deception_triggers_artifact_time on deception_triggers(artifact_id, observed_at desc);
create index if not exists idx_deception_triggers_ip on deception_triggers(source_ip) where source_ip is not null;
alter table deception_triggers enable row level security;
create policy deception_triggers_tenant_select on deception_triggers for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

revoke all on deception_triggers from anon, authenticated;
revoke all on deception_artifacts from anon;
grant select, insert on deception_artifacts to authenticated;
grant select on deception_triggers to authenticated;

create or replace function deception_record_trigger(
    p_token_hash text,
    p_source_ip inet default null,
    p_forwarded_for text default null,
    p_user_agent text default null,
    p_request_method text default null,
    p_request_path text default null,
    p_source_country text default null,
    p_source_asn bigint default null,
    p_source_org text default null,
    p_evidence jsonb default '{}'::jsonb
) returns table (trigger_id uuid, tenant_id uuid, artifact_id uuid, severity text, artifact_type text)
language plpgsql
as $$
declare
    a deception_artifacts%rowtype;
    t uuid;
begin
    select * into a from deception_artifacts where token_hash = p_token_hash and enabled = true for update;
    if not found then return; end if;
    insert into deception_triggers(
        tenant_id, artifact_id, source_ip, forwarded_for, user_agent,
        request_method, request_path, source_country, source_asn, source_org,
        evidence, alert_severity
    ) values (
        a.tenant_id, a.id, p_source_ip, left(p_forwarded_for, 2048), left(p_user_agent, 2048),
        left(p_request_method, 32), left(p_request_path, 2048), left(p_source_country, 2), p_source_asn,
        left(p_source_org, 512), coalesce(p_evidence, '{}'::jsonb),
        case when a.severity = 'medium' then 'high' else a.severity end
    ) returning id into t;
    update deception_artifacts set last_triggered_at = now(), trigger_count = trigger_count + 1 where id = a.id;
    return query select t, a.tenant_id, a.id,
        case when a.severity = 'medium' then 'high' else a.severity end, a.artifact_type;
end;
$$;

revoke all on function deception_record_trigger(text, inet, text, text, text, text, text, bigint, text, jsonb) from public, anon, authenticated;
grant execute on function deception_record_trigger(text, inet, text, text, text, text, text, bigint, text, jsonb) to service_role;
