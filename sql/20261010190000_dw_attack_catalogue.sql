-- Official MITRE ATT&CK catalogue cache and idempotent attribution delivery indexes.
create table if not exists public.dw_attack_techniques (
  technique_id text primary key check (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
  name text not null,
  description text not null default '',
  platforms jsonb not null default '[]'::jsonb,
  tactics jsonb not null default '[]'::jsonb,
  url text,
  stix_id text,
  updated_at timestamptz not null default now()
);
create table if not exists public.dw_attack_catalogue_state (
  catalogue_id text primary key,
  source_url text,
  last_success_at timestamptz,
  technique_count integer not null default 0,
  last_error_code text,
  updated_at timestamptz not null default now()
);
alter table public.dw_attack_techniques enable row level security;
alter table public.dw_attack_catalogue_state enable row level security;
revoke all on public.dw_attack_techniques, public.dw_attack_catalogue_state from anon, authenticated;
grant select, insert, update, delete on public.dw_attack_techniques, public.dw_attack_catalogue_state to service_role;

-- PostgreSQL unique constraints allow multiple NULL assessment IDs. A non-partial
-- index is required for PostgREST's ON CONFLICT target inference.
create unique index if not exists dw_attribution_alert_assessment_event_uidx
  on public.dw_attribution_alert_outbox(tenant_id, assessment_id, event_type);
