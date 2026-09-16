-- Sentinel Dark Web Monitoring: tenant-scoped watchlists, immutable findings,
-- deduplicated alerts, ransomware intelligence, and service-role ingestion.

create table if not exists public.dw_sources (
    id text primary key,
    name text not null,
    kind text not null check (kind in ('breach_dump','paste','forum','telegram','marketplace','ransomware_leak','code_repo','custom')),
    endpoint text,
    auth_ref text,
    enabled boolean not null default true,
    last_pull_at timestamptz,
    last_status text,
    poll_interval_seconds integer not null default 900 check (poll_interval_seconds between 60 and 604800),
    created_at timestamptz not null default now()
);

create table if not exists public.dw_watchlist (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    kind text not null check (kind in ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id')),
    value text not null,
    value_hash text not null,
    label text,
    severity text not null default 'high' check (severity in ('medium','high','critical')),
    notify_channels text[] not null default array['critical'],
    created_by uuid references auth.users(id) on delete set null,
    created_at timestamptz not null default now(),
    unique (tenant_id, kind, value_hash)
);
create index if not exists dw_watchlist_lookup_idx on public.dw_watchlist(kind, value_hash);
create index if not exists dw_watchlist_tenant_idx on public.dw_watchlist(tenant_id, kind);
alter table public.dw_watchlist enable row level security;

create table if not exists public.dw_findings (
    id bigint generated always as identity primary key,
    source_id text not null references public.dw_sources(id),
    content_hash text not null,
    kind text not null check (kind in ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id')),
    matched_value text not null,
    context text,
    source_url text,
    source_metadata jsonb not null default '{}'::jsonb,
    severity text not null default 'medium' check (severity in ('medium','high','critical')),
    first_seen timestamptz not null default now(),
    tenant_id uuid references public.tenants(id) on delete cascade,
    watchlist_id uuid references public.dw_watchlist(id) on delete set null,
    unique (source_id, content_hash)
);
create index if not exists dw_findings_tenant_idx on public.dw_findings(tenant_id, first_seen desc) where tenant_id is not null;
create index if not exists dw_findings_source_idx on public.dw_findings(source_id, first_seen desc);
alter table public.dw_findings enable row level security;

create table if not exists public.dw_alerts (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    watchlist_id uuid not null references public.dw_watchlist(id) on delete cascade,
    finding_id bigint not null references public.dw_findings(id) on delete cascade,
    kind text not null,
    severity text not null check (severity in ('medium','high','critical')),
    title text not null,
    summary text,
    status text not null default 'new' check (status in ('new','acknowledged','investigating','remediated','false_positive')),
    assigned_to uuid references auth.users(id) on delete set null,
    acknowledged_at timestamptz,
    remediated_at timestamptz,
    notes text,
    case_id uuid references public.crime_cases(id) on delete set null,
    created_at timestamptz not null default now(),
    unique (watchlist_id, finding_id)
);
create index if not exists dw_alerts_tenant_idx on public.dw_alerts(tenant_id, created_at desc);
create index if not exists dw_alerts_status_idx on public.dw_alerts(tenant_id, status);
alter table public.dw_alerts enable row level security;

create table if not exists public.ransomware_victims (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references public.tenants(id) on delete cascade,
    group_name text not null,
    victim_name text not null,
    victim_domain text,
    country text,
    sector text,
    data_size text,
    claim_url text,
    published_at timestamptz,
    countdown_at timestamptz,
    matched boolean not null default false,
    created_at timestamptz not null default now()
);
create index if not exists ransomware_tenant_idx on public.ransomware_victims(tenant_id, published_at desc);
create index if not exists ransomware_domain_idx on public.ransomware_victims(victim_domain);
alter table public.ransomware_victims enable row level security;

create table if not exists public.dw_stats (
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    day date not null,
    findings_total integer not null default 0,
    alerts_high integer not null default 0,
    alerts_critical integer not null default 0,
    remediated integer not null default 0,
    primary key (tenant_id, day)
);
alter table public.dw_stats enable row level security;

-- Ingestion is service-role only. The function never accepts or stores a password;
-- callers must provide a normalized identifier and redacted context.
create or replace function public.record_dw_finding(
    p_source_id text,
    p_content_hash text,
    p_kind text,
    p_matched_value text,
    p_context text,
    p_severity text,
    p_source_url text,
    p_metadata jsonb,
    p_tenant_id uuid,
    p_watchlist_id uuid
) returns table(finding_id bigint, alert_id uuid, detection_id uuid)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_finding bigint;
    v_alert uuid;
    v_detection uuid;
    v_watch_tenant uuid;
    v_score real;
    v_verdict text;
    v_title text;
    v_severity text;
begin
    if p_source_id is null or p_content_hash is null or length(trim(p_content_hash)) <> 64 then
        raise exception 'invalid source or content hash';
    end if;
    if p_kind not in ('email','domain','ip','wallet','phone','company_name','executive_name','api_key_hash','employee_id','customer_id') then
        raise exception 'invalid finding kind';
    end if;
    if p_severity not in ('medium','high','critical') then
        raise exception 'invalid finding severity';
    end if;
    if p_watchlist_id is not null then
        select tenant_id into v_watch_tenant from public.dw_watchlist where id = p_watchlist_id;
        if v_watch_tenant is null or p_tenant_id is null or v_watch_tenant <> p_tenant_id then
            raise exception 'watchlist tenant mismatch';
        end if;
    elsif p_tenant_id is not null then
        raise exception 'matched finding requires watchlist';
    end if;

    insert into public.dw_findings(source_id, content_hash, kind, matched_value, context, source_url, source_metadata, severity, tenant_id, watchlist_id)
    values (p_source_id, p_content_hash, p_kind, left(p_matched_value, 512), left(p_context, 2000), left(p_source_url, 2048), coalesce(p_metadata, '{}'::jsonb), p_severity, p_tenant_id, p_watchlist_id)
    on conflict (source_id, content_hash) do update
      set tenant_id = coalesce(excluded.tenant_id, dw_findings.tenant_id),
          watchlist_id = coalesce(excluded.watchlist_id, dw_findings.watchlist_id)
    returning id into v_finding;

    if p_tenant_id is not null and p_watchlist_id is not null then
        v_severity := p_severity;
        v_title := case p_kind
            when 'email' then 'Credential exposure detected'
            when 'domain' then 'Domain exposure detected'
            when 'wallet' then 'Wallet exposure detected'
            else 'Monitored data exposure detected'
        end;
        insert into public.dw_alerts(tenant_id, watchlist_id, finding_id, kind, severity, title, summary)
        values (p_tenant_id, p_watchlist_id, v_finding, p_kind, v_severity, v_title, left(coalesce(p_context, 'Monitored identifier observed in an external source.'), 2000))
        on conflict (watchlist_id, finding_id) do update set summary = excluded.summary
        returning id into v_alert;

        v_score := case v_severity when 'critical' then 0.99 when 'high' then 0.90 else 0.75 end;
        v_verdict := case when v_severity = 'critical' then 'malicious' else 'suspicious' end;
        insert into public.detections(tenant_id, device_id, event_id, detector, score, verdict, reasons, evidence, mitre_technique, processed_by_playbooks, processed_by_autocase)
        values (p_tenant_id, null, null, 'darkweb', v_score, v_verdict, array['external_exposure','darkweb_watchlist_match'], jsonb_build_object('alert_id', v_alert, 'finding_id', v_finding, 'source_id', p_source_id, 'kind', p_kind), 'T1589', false, false)
        on conflict do nothing
        returning id into v_detection;
    end if;

    return query select v_finding, v_alert, v_detection;
end;
$$;

revoke all on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) from public, anon, authenticated;
grant execute on function public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid) to service_role;

insert into public.dw_sources(id,name,kind,endpoint,poll_interval_seconds) values
('hibp','Have I Been Pwned','breach_dump','https://haveibeenpwned.com/api/v3',86400),
('ransomwatch','Ransomwatch','ransomware_leak','https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json',1800),
('pastebin_public','Paste public feed','paste','https://pastebin.com/feed/',900),
('telegram_public','Telegram public web previews','telegram','https://t.me/s/',900),
('github_code','GitHub code search','code_repo','https://api.github.com/search/code',3600)
on conflict(id) do nothing;

-- Tenant-visible policies. Service-role ingestion bypasses these policies.
drop policy if exists dw_watchlist_tenant on public.dw_watchlist;
create policy dw_watchlist_tenant on public.dw_watchlist for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create policy dw_watchlist_insert on public.dw_watchlist for insert with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create policy dw_watchlist_delete on public.dw_watchlist for delete using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

drop policy if exists dw_findings_tenant on public.dw_findings;
create policy dw_findings_tenant on public.dw_findings for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

drop policy if exists dw_alerts_tenant on public.dw_alerts;
create policy dw_alerts_tenant on public.dw_alerts for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
create policy dw_alerts_update on public.dw_alerts for update using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid) with check (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

drop policy if exists ransomware_tenant on public.ransomware_victims;
create policy ransomware_tenant on public.ransomware_victims for select using (tenant_id is null or tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);

drop policy if exists dw_stats_tenant on public.dw_stats;
create policy dw_stats_tenant on public.dw_stats for select using (tenant_id = nullif(auth.jwt() ->> 'tenant_id','')::uuid);
