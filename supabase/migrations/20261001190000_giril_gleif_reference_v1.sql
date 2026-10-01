begin;

-- GLEIF Level-1 reference records. Raw source payloads are intentionally not stored.
create table if not exists public.giril_ref_lei_entities (
  lei char(20) primary key check(lei ~ '^[A-Z0-9]{20}$'),
  legal_name text not null,
  entity_status text,
  jurisdiction_country_iso2 char(2),
  registration_authority_id text,
  registration_authority_entity_id text,
  legal_form_code text,
  legal_address jsonb not null default '{}'::jsonb check(jsonb_typeof(legal_address)='object'),
  headquarters_address jsonb not null default '{}'::jsonb check(jsonb_typeof(headquarters_address)='object'),
  initial_registration_date date,
  last_update_date date,
  next_renewal_date date,
  source_id uuid not null references public.giril_ref_sources(id) on delete restrict,
  source_version text not null,
  source_manifest_hash text not null check(source_manifest_hash ~ '^[0-9a-f]{64}$'),
  effective_at timestamptz,
  updated_at timestamptz not null default now()
);

create index if not exists giril_lei_name_idx on public.giril_ref_lei_entities using gin (to_tsvector('simple', legal_name));
create index if not exists giril_lei_country_idx on public.giril_ref_lei_entities(jurisdiction_country_iso2);
create index if not exists giril_lei_status_idx on public.giril_ref_lei_entities(entity_status);

alter table public.giril_ref_lei_entities enable row level security;
drop policy if exists giril_ref_lei_entities_read on public.giril_ref_lei_entities;
create policy giril_ref_lei_entities_read on public.giril_ref_lei_entities for select to authenticated using(true);
revoke all on public.giril_ref_lei_entities from anon;
grant select on public.giril_ref_lei_entities to authenticated;
revoke insert,update,delete on public.giril_ref_lei_entities from anon,authenticated;

commit;
