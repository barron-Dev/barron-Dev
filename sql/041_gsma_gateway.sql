create table if not exists gsma_operators (
    id text primary key, name text not null, country text not null, mcc_mnc text not null,
    oidc_issuer text not null, oidc_client_id text not null, oidc_secret_ref text not null,
    scopes text[] not null default '{}', enabled boolean not null default true, created_at timestamptz not null default now()
);
insert into gsma_operators (id,name,country,mcc_mnc,oidc_issuer,oidc_client_id,oidc_secret_ref) values
('mtn-ng','MTN Nigeria','NG','621-30','https://oidc.mtn.ng','cyclothone','vault://gsma/mtn_ng'),
('safaricom-ke','Safaricom','KE','639-02','https://oidc.safaricom.co.ke','cyclothone','vault://gsma/safaricom'),
('mtn-bj','MTN Benin','BJ','616-01','https://oidc.mtn.bj','cyclothone','vault://gsma/mtn_bj'),
('orange-ci','Orange Côte d''Ivoire','CI','602-01','https://oidc.orange.ci','cyclothone','vault://gsma/orange_ci')
on conflict (id) do nothing;

create table if not exists gsma_signals (
    id bigserial primary key, tenant_id uuid not null references tenants(id) on delete cascade,
    e164_hash text not null, signal_type text not null check (signal_type in
      ('sim_swap','device_location','number_verification','device_swap','roaming','call_forwarding')),
    operator_id text references gsma_operators(id), result jsonb not null default '{}'::jsonb,
    confidence real not null default 0.5 check (confidence between 0 and 1),
    risk_delta real not null default 0, observed_at timestamptz not null default now()
);
create index if not exists idx_gsma_signals_hash on gsma_signals(tenant_id,e164_hash,observed_at desc);
create index if not exists idx_gsma_signals_type on gsma_signals(tenant_id,signal_type,observed_at desc);
alter table gsma_signals enable row level security;
drop policy if exists gsma_signals_tenant on gsma_signals;
create policy gsma_signals_tenant on gsma_signals using (tenant_id=(auth.jwt()->>'tenant_id')::uuid);

create table if not exists gsma_tokens (
    tenant_id uuid not null references tenants(id) on delete cascade,
    operator_id text not null references gsma_operators(id) on delete cascade,
    access_token text not null, refresh_token text, scopes text[] not null default '{}',
    expires_at timestamptz not null, refresh_expires_at timestamptz, updated_at timestamptz not null default now(),
    primary key (tenant_id,operator_id)
);
alter table gsma_tokens enable row level security;
drop policy if exists gsma_tokens_tenant on gsma_tokens;
create policy gsma_tokens_tenant on gsma_tokens using (tenant_id=(auth.jwt()->>'tenant_id')::uuid);
revoke all on gsma_tokens from anon,authenticated;