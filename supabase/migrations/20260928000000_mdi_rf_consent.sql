begin;
create table if not exists public.mdi_observer_consent(observer_id uuid primary key references auth.users(id) on delete cascade,rf_scan boolean not null default false,gnss_share boolean not null default false,wifi_share boolean not null default false,ble_share boolean not null default false,purpose text not null,granted_at timestamptz not null default now(),expires_at timestamptz not null,revoked_at timestamptz);
alter table public.mdi_observer_consent enable row level security;
drop policy if exists mdi_observer_consent_self on public.mdi_observer_consent;
create policy mdi_observer_consent_self on public.mdi_observer_consent for all to authenticated using(observer_id=(select auth.uid())) with check(observer_id=(select auth.uid()));
revoke all on public.mdi_observer_consent from anon;
commit;