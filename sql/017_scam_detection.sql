-- Sentinel scam-call/message detection, migration 017.
-- Raw message/audio content is not retained by these tables unless explicitly consented.

create table if not exists scam_numbers (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    e164 text not null,
    country text not null check (country ~ '^[A-Z]{2}$'),
    category text not null check (category in ('otp_theft','bank_impersonation','prize_scam','investment','romance','tech_support','delivery','government_impersonation','crypto','sextortion','loan','job_offer','other')),
    severity text not null default 'medium' check (severity in ('low','medium','high','critical')),
    report_count integer not null default 1 check (report_count >= 0),
    confidence real not null default 0.5 check (confidence between 0 and 1),
    carrier text,
    line_type text check (line_type in ('mobile','landline','voip','tollfree','unknown')),
    stir_shaken text check (stir_shaken in ('A','B','C','none','unknown')),
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    blocked boolean not null default false,
    notes text,
    unique (tenant_id, e164)
);
create index if not exists idx_scam_numbers_lookup on scam_numbers(e164);
create index if not exists idx_scam_numbers_tenant on scam_numbers(tenant_id, category);
create index if not exists idx_scam_numbers_blocked on scam_numbers(tenant_id) where blocked = true;
alter table scam_numbers enable row level security;
create policy scam_numbers_read on scam_numbers for select to authenticated
    using (tenant_id is null or tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

create table if not exists scam_reports (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants(id) on delete cascade,
    reporter_user uuid references auth.users(id) on delete set null,
    device_id uuid references devices(id) on delete set null,
    channel text not null check (channel in ('call','sms','whatsapp','telegram','signal','other')),
    direction text not null check (direction in ('inbound','outbound')),
    e164 text,
    sender_id text,
    text_hash text,
    text_preview text check (text_preview is null or length(text_preview) <= 200),
    category text not null,
    confidence real not null default 0.5 check (confidence between 0 and 1),
    signals jsonb not null default '[]'::jsonb,
    urls text[] not null default '{}',
    wallets text[] not null default '{}',
    attachments jsonb not null default '[]'::jsonb,
    status text not null default 'pending' check (status in ('pending','confirmed','rejected','duplicate')),
    reviewed_by uuid references auth.users(id) on delete set null,
    reviewed_at timestamptz,
    created_at timestamptz not null default now()
);
create index if not exists idx_scam_reports_tenant on scam_reports(tenant_id, created_at desc);
create index if not exists idx_scam_reports_status on scam_reports(tenant_id, status);
create index if not exists idx_scam_reports_e164 on scam_reports(e164) where e164 is not null;
alter table scam_reports enable row level security;
create policy scam_reports_tenant on scam_reports for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

create table if not exists message_samples (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    text_hash text not null,
    normalized text not null,
    label integer not null check (label in (0,1)),
    category text,
    country text,
    language text not null default 'en',
    source text not null default 'user_report',
    created_at timestamptz not null default now(),
    unique (text_hash, tenant_id)
);
create index if not exists idx_message_samples_label on message_samples(label, country);
alter table message_samples enable row level security;
create policy message_samples_tenant on message_samples for select to authenticated
    using (tenant_id is null or tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

create table if not exists voice_features (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    audio_hash text not null,
    duration_ms integer not null check (duration_ms > 0),
    features jsonb not null,
    label integer check (label in (0,1)),
    model_version integer,
    score real check (score is null or score between 0 and 1),
    country text,
    created_at timestamptz not null default now()
);
create index if not exists idx_voice_features_label on voice_features(label);
alter table voice_features enable row level security;
create policy voice_features_tenant on voice_features for select to authenticated
    using (tenant_id is null or tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

create table if not exists scam_campaigns (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants(id) on delete cascade,
    name text not null,
    category text not null,
    status text not null default 'active' check (status in ('active','contained','closed')),
    e164_list text[] not null default '{}',
    url_list text[] not null default '{}',
    wallet_list text[] not null default '{}',
    template_hash text,
    report_count integer not null default 0 check (report_count >= 0),
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    notes text
);
create index if not exists idx_campaigns_tenant on scam_campaigns(tenant_id, status);
alter table scam_campaigns enable row level security;
create policy campaigns_tenant on scam_campaigns for select to authenticated
    using (tenant_id is null or tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

create table if not exists callkit_blocklist (
    tenant_id uuid not null references tenants(id) on delete cascade,
    region text not null,
    version bigint not null default 1,
    entry_count integer not null default 0 check (entry_count >= 0),
    payload_url text not null,
    payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-fA-F]{64}$'),
    built_at timestamptz not null default now(),
    primary key (tenant_id, region)
);
alter table callkit_blocklist enable row level security;
create policy callkit_blocklist_tenant on callkit_blocklist for select to authenticated
    using (tenant_id = (select (auth.jwt() ->> 'tenant_id')::uuid));

grant select on scam_numbers, scam_reports, message_samples, voice_features, scam_campaigns, callkit_blocklist to authenticated;
