begin;

alter table public.mdi_observer_consent
  add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;

create index if not exists mdi_observer_consent_tenant_observer_idx
  on public.mdi_observer_consent(tenant_id, observer_id);

alter table public.mdi_rf_observations
  add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;

create index if not exists mdi_rf_observations_tenant_observed_idx
  on public.mdi_rf_observations(tenant_id, observed_at desc);

alter table public.mdi_rf_threats
  add column if not exists tenant_id uuid references public.tenants(id) on delete cascade;

create index if not exists mdi_rf_threats_tenant_created_idx
  on public.mdi_rf_threats(tenant_id, created_at desc);

commit;