-- Cyclothone identity evidence graph foundation.
-- Additive only. Do not apply to production until API authorization and E2E tests pass.
-- Store provenance and minimal evidence; never store passwords, session cookies,
-- raw credential dumps, biometric templates, or inferred identity as fact.

begin;

create table if not exists public.identity_entities (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  entity_type text not null check (entity_type in (
    'person','organization','social_account','email','phone','username',
    'ip_address','domain','telegram_channel','breach_record','image_reference'
  )),
  canonical_value text not null check (length(btrim(canonical_value)) between 1 and 1000),
  value_hash text not null check (value_hash ~ '^[0-9a-f]{64}$'),
  display_label text,
  attributes jsonb not null default '{}'::jsonb check (jsonb_typeof(attributes) = 'object'),
  confidence numeric(4,3) not null default 0.500 check (confidence >= 0 and confidence <= 1),
  review_state text not null default 'unreviewed'
    check (review_state in ('unreviewed','needs_review','confirmed','rejected')),
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, entity_type, value_hash),
  unique (tenant_id, id)
);

create table if not exists public.identity_relationships (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  source_entity_id uuid not null,
  target_entity_id uuid not null,
  relation_type text not null check (relation_type in (
    'has_account','uses_email','uses_username','same_person','posted_in',
    'exposed_in','linked_to','associated_with','hosted_on','mentions'
  )),
  confidence numeric(4,3) not null default 0.500 check (confidence >= 0 and confidence <= 1),
  review_state text not null default 'unreviewed'
    check (review_state in ('unreviewed','needs_review','confirmed','rejected')),
  rationale text not null check (length(btrim(rationale)) between 1 and 2000),
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, id),
  check (source_entity_id <> target_entity_id),
  foreign key (tenant_id, source_entity_id)
    references public.identity_entities(tenant_id, id) on delete cascade,
  foreign key (tenant_id, target_entity_id)
    references public.identity_entities(tenant_id, id) on delete cascade
);

create table if not exists public.identity_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  entity_id uuid,
  relationship_id uuid,
  source_id text not null check (length(btrim(source_id)) between 1 and 200),
  source_url text,
  evidence_type text not null check (evidence_type in (
    'public_profile','public_post','authorized_api_record','breach_notice',
    'customer_supplied','technical_observation','analyst_note'
  )),
  access_mode text not null check (access_mode in (
    'public','authorized_api','authorized_private','customer_supplied'
  )),
  observed_at timestamptz,
  published_at timestamptz,
  collected_at timestamptz not null default now(),
  content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
  redacted_summary text check (redacted_summary is null or length(redacted_summary) <= 2000),
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  created_at timestamptz not null default now(),
  check (num_nonnulls(entity_id, relationship_id) = 1),
  foreign key (tenant_id, entity_id)
    references public.identity_entities(tenant_id, id) on delete cascade,
  foreign key (tenant_id, relationship_id)
    references public.identity_relationships(tenant_id, id) on delete cascade,
  unique nulls not distinct (tenant_id, source_id, content_hash, entity_id, relationship_id)
);

create index if not exists identity_entities_tenant_type_idx
  on public.identity_entities (tenant_id, entity_type, created_at desc);
create index if not exists identity_entities_value_hash_idx
  on public.identity_entities (tenant_id, value_hash);
create index if not exists identity_relationships_source_idx
  on public.identity_relationships (tenant_id, source_entity_id, relation_type);
create index if not exists identity_relationships_target_idx
  on public.identity_relationships (tenant_id, target_entity_id, relation_type);
create index if not exists identity_evidence_entity_recent_idx
  on public.identity_evidence (tenant_id, entity_id, collected_at desc)
  where entity_id is not null;
create index if not exists identity_evidence_relationship_recent_idx
  on public.identity_evidence (tenant_id, relationship_id, collected_at desc)
  where relationship_id is not null;
create index if not exists identity_evidence_source_idx
  on public.identity_evidence (tenant_id, source_id, collected_at desc);

alter table public.identity_entities enable row level security;
alter table public.identity_relationships enable row level security;
alter table public.identity_evidence enable row level security;

drop policy if exists identity_entities_tenant_select on public.identity_entities;
create policy identity_entities_tenant_select on public.identity_entities
  for select to authenticated
  using (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);
drop policy if exists identity_entities_tenant_insert on public.identity_entities;
create policy identity_entities_tenant_insert on public.identity_entities
  for insert to authenticated
  with check (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);
drop policy if exists identity_entities_tenant_update on public.identity_entities;
create policy identity_entities_tenant_update on public.identity_entities
  for update to authenticated
  using (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid)
  with check (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);

drop policy if exists identity_relationships_tenant_select on public.identity_relationships;
create policy identity_relationships_tenant_select on public.identity_relationships
  for select to authenticated
  using (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);
drop policy if exists identity_relationships_tenant_insert on public.identity_relationships;
create policy identity_relationships_tenant_insert on public.identity_relationships
  for insert to authenticated
  with check (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);
drop policy if exists identity_relationships_tenant_update on public.identity_relationships;
create policy identity_relationships_tenant_update on public.identity_relationships
  for update to authenticated
  using (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid)
  with check (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);

drop policy if exists identity_evidence_tenant_select on public.identity_evidence;
create policy identity_evidence_tenant_select on public.identity_evidence
  for select to authenticated
  using (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);
drop policy if exists identity_evidence_tenant_insert on public.identity_evidence;
create policy identity_evidence_tenant_insert on public.identity_evidence
  for insert to authenticated
  with check (tenant_id = (nullif(auth.jwt() ->> 'tenant_id', ''))::uuid);

grant select, insert, update on public.identity_entities to authenticated;
grant select, insert, update on public.identity_relationships to authenticated;
grant select, insert on public.identity_evidence to authenticated;

commit;
