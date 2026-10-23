-- Class-level evidence table policy registry. Preview-only until isolated migration tests pass.
-- Must run after the PR #76 trust and evidence foundations on a documented base.
begin;

create table if not exists public.dw_table_security_policy (
  tablename text primary key check (tablename ~ '^dw_[a-z0-9_]+$'),
  append_only boolean not null,
  grants_to_service_role text[] not null,
  notes text not null,
  check (cardinality(grants_to_service_role) > 0),
  check (grants_to_service_role <@ array['SELECT','INSERT','UPDATE','DELETE']::text[])
);

insert into public.dw_table_security_policy(tablename, append_only, grants_to_service_role, notes)
values
 ('dw_onion_probe_evidence', true, array['SELECT'], 'Raw probe evidence is written only by the proof-bound RPC'),
 ('dw_source_health_events', true, array['SELECT'], 'Source health observations are written only by trusted RPCs'),
 ('dw_evidence_log', true, array['SELECT'], 'Hash-chained evidence; direct app writes stay disabled until trusted writer exists'),
 ('dw_evidence_ots_receipts', false, array['SELECT'], 'Mutable verifier state machine; only trusted verifier may write'),
 ('dw_evidence_tsa_receipts', false, array['SELECT'], 'Timestamp-token verification; direct app writes stay disabled'),
 ('dw_merkle_anchors', false, array['SELECT'], 'Anchor state may advance only through trusted verifier'),
 ('dw_sanitized_content', true, array['SELECT'], 'Versioned derived content; trusted sanitizer writer is not yet wired'),
 ('dw_client_auth_credentials', false, array['SELECT'], 'Encrypted client-auth material; KMS writer is not yet wired'),
 ('dw_circuit_assignments', false, array['SELECT'], 'Tor isolation state; trusted circuit manager is not yet wired'),
 ('dw_mirror_integrity', true, array['SELECT'], 'Publisher signature verifier output; direct writes disabled'),
 ('dw_content_fingerprints', true, array['SELECT'], 'Derived content fingerprints; trusted processor is not yet wired'),
 ('dw_publisher_key_pins', false, array['SELECT'], 'Publisher pin lifecycle; direct writes disabled'),
 ('dw_content_embeddings', true, array['SELECT'], 'Derived embeddings; trusted processor is not yet wired'),
 ('dw_source_anomaly_events', true, array['SELECT'], 'Anomaly signals are evidence, never findings by themselves'),
 ('dw_descriptor_health', true, array['SELECT'], 'Descriptor observations; trusted Tor collector is not yet wired'),
 ('dw_trust_honeypot_observations', true, array['SELECT'], 'Deception telemetry is append-only and isolated from findings'),
 ('dw_trust_canary_events', true, array['SELECT'], 'Signed-provider canary ingest; direct caller attestations disabled'),
 ('dw_source_health', false, array['SELECT'], 'Source health state is written only by trusted workers'),
 ('dw_discovery_job_runs', false, array['SELECT'], 'Worker state is read-only until the fenced writer is integrated'),
 ('dw_discovery_dead_letters', false, array['SELECT'], 'Dead-letter state is read-only until the review workflow is authorized'),
 ('dw_entities', false, array['SELECT'], 'Entity resolution is read-only until tenant-authorized writer is integrated'),
 ('dw_entity_aliases', true, array['SELECT'], 'Entity aliases are immutable evidence derivatives'),
 ('dw_entity_links', false, array['SELECT'], 'Entity-link review state is read-only until authorized workflow exists'),
 ('dw_entity_mentions', true, array['SELECT'], 'Evidence mentions are immutable derivatives'),
 ('dw_content_translations', true, array['SELECT'], 'Translations are immutable, provenance-linked derivatives'),
 ('dw_ner_extractions', true, array['SELECT'], 'NER extractions are immutable, provenance-linked derivatives')
on conflict (tablename) do update
set append_only = excluded.append_only,
    grants_to_service_role = excluded.grants_to_service_role,
    notes = excluded.notes;

do $$
declare unregistered text;
begin
  select string_agg(t.tablename, ', ' order by t.tablename)
    into unregistered
    from pg_tables t
   where t.schemaname = 'public'
     and (
       t.tablename like 'dw\_%evidence%' escape '\'
       or t.tablename like 'dw\_%proofs' escape '\'
       or t.tablename like 'dw\_%events' escape '\'
       or t.tablename like 'dw\_trust\_%' escape '\'
       or t.tablename like 'dw\_%\_health' escape '\'
       or t.tablename like 'dw\_%\_integrity' escape '\'
       or t.tablename like 'dw\_%\_fingerprints' escape '\'
       or t.tablename like 'dw\_%\_embeddings' escape '\'
       or t.tablename like 'dw\_%\_credentials' escape '\'
       or t.tablename like 'dw\_%\_assignments' escape '\'
       or t.tablename like 'dw\_%\_pins' escape '\'
       or t.tablename like 'dw\_%\_observations' escape '\'
       or t.tablename like 'dw\_discovery\_%' escape '\'
       or t.tablename like 'dw\_entity\_%' escape '\'
       or t.tablename = 'dw_entities'
       or t.tablename like 'dw\_content\_%' escape '\'
       or t.tablename like 'dw\_%\_translations' escape '\'
       or t.tablename like 'dw\_%\_extractions' escape '\'
       or t.tablename like 'dw\_sanitized\_%' escape '\'
       or t.tablename like 'dw\_merkle\_%' escape '\'
     )
     and not exists (
       select 1 from public.dw_table_security_policy p
        where p.tablename = t.tablename
     );
  if unregistered is not null then
    raise exception 'unregistered DW trust/evidence tables; add explicit policy before applying: %', unregistered;
  end if;

  -- A registered name must resolve to a real table. Fail closed on stale entries.
  select string_agg(p.tablename, ', ' order by p.tablename)
    into unregistered
    from public.dw_table_security_policy p
   where to_regclass(format('public.%I', p.tablename)) is null;
  if unregistered is not null then
    raise exception 'evidence policy registry references missing tables: %', unregistered;
  end if;
end $$;

create or replace function public.dw_block_mutation()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  raise exception '% is append-only; write a new version instead', tg_table_name
    using errcode = '55000';
end
$$;

do $$
declare r record;
begin
  for r in
    select p.*
      from public.dw_table_security_policy p
     order by p.tablename
  loop
    execute format('alter table public.%I enable row level security', r.tablename);
    execute format('revoke all on table public.%I from public, anon, authenticated', r.tablename);
    execute format(
      'grant %s on table public.%I to service_role',
      array_to_string(r.grants_to_service_role, ', '),
      r.tablename
    );

    if r.append_only then
      execute format('revoke update, delete on table public.%I from service_role', r.tablename);
      execute format('drop trigger if exists %I on public.%I', r.tablename || '_policy_no_mutate', r.tablename);
      execute format(
        'create trigger %I before update or delete on public.%I for each row execute function public.dw_block_mutation()',
        r.tablename || '_policy_no_mutate', r.tablename
      );
    else
      execute format('drop trigger if exists %I on public.%I', r.tablename || '_policy_no_mutate', r.tablename);
    end if;
  end loop;
end $$;

revoke all on public.dw_table_security_policy from public, anon, authenticated, service_role;
revoke all on sequence public.dw_evidence_log_seq_seq from public, anon, authenticated, service_role;
alter table public.dw_table_security_policy enable row level security;
comment on table public.dw_table_security_policy is
  'Fail-closed registry for DW evidence table RLS, service-role grants, and mutability policy. Every dw_*evidence* table must be registered.';

commit;
