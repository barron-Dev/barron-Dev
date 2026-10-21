-- Evidence integrity, processing idempotency, entity graph and language provenance.
-- Additive only. Do not apply to production without explicit release approval.
begin;
create table if not exists public.dw_discovery_job_runs (
 id uuid primary key default gen_random_uuid(),
 queue_job_id bigint not null references public.dw_source_discovery_queue(id) on delete restrict,
 idempotency_key text not null unique check(idempotency_key ~ '^[0-9a-f]{64}$'),
 job_kind text not null,
 status text not null default 'claimed' check(status in ('claimed','running','succeeded','retryable_failed','dead')),
 attempts integer not null default 0 check(attempts>=0), lease_token uuid, claimed_at timestamptz,
 next_attempt_at timestamptz, last_error_code text, evidence_seq bigint, started_at timestamptz,
 finished_at timestamptz, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index if not exists dw_discovery_job_runs_status_idx on public.dw_discovery_job_runs(status,next_attempt_at);
create table if not exists public.dw_discovery_dead_letters (
 id uuid primary key default gen_random_uuid(),
 queue_job_id bigint not null references public.dw_source_discovery_queue(id) on delete restrict,
 idempotency_key text not null unique check(idempotency_key ~ '^[0-9a-f]{64}$'),
 final_attempt integer not null check(final_attempt>=1), error_code text not null,
 safe_metadata jsonb not null default '{}'::jsonb, dead_lettered_at timestamptz not null default now(),
 reviewed_at timestamptz, reviewed_by uuid,
 disposition text check(disposition is null or disposition in ('retry_approved','discard_approved','quarantined'))
);
create table if not exists public.dw_source_health (
 source_id uuid primary key references public.dw_onion_seeds(id) on delete restrict,
 state text not null default 'unknown' check(state in ('unknown','ok','degraded','unreachable','auth_failed','tor_unavailable')),
 consecutive_failures integer not null default 0 check(consecutive_failures>=0),
 next_probe_at timestamptz, last_probe_at timestamptz, last_error_code text, updated_at timestamptz not null default now()
);
create table if not exists public.dw_evidence_log (
 seq bigserial primary key, evidence_id uuid not null unique default gen_random_uuid(),
 tenant_id uuid not null references public.tenants(id) on delete restrict,
 source_id uuid not null references public.dw_onion_seeds(id) on delete restrict,
 queue_job_id bigint references public.dw_source_discovery_queue(id) on delete restrict,
 idempotency_key text not null unique check(idempotency_key ~ '^[0-9a-f]{64}$'),
 archive_uri text not null, archive_format text not null default 'WARC/1.1' check(archive_format='WARC/1.1'),
 warc_record_id text not null, capture_kind text not null check(capture_kind in ('response','revisit','metadata_only')),
 response_status integer check(response_status is null or response_status between 100 and 599),
 content_type text, content_length bigint not null check(content_length>=0),
 content_sha256 text not null check(content_sha256 ~ '^[0-9a-f]{64}$'),
 archive_sha256 text not null check(archive_sha256 ~ '^[0-9a-f]{64}$'),
 metadata_sha256 text not null check(metadata_sha256 ~ '^[0-9a-f]{64}$'),
 captured_at timestamptz not null, prev_hash text not null default repeat('0',64) check(prev_hash ~ '^[0-9a-f]{64}$'),
 row_hash text not null default repeat('0',64) check(row_hash ~ '^[0-9a-f]{64}$'),
 ots_proof_uri text, ots_status text not null default 'not_requested' check(ots_status in ('not_requested','pending','confirmed','verification_failed')),
 ots_confirmed_at timestamptz, tsa_token_uri text, tsa_serial text, tsa_policy_oid text, tsa_verified_at timestamptz,
 created_at timestamptz not null default now()
);
create index if not exists dw_evidence_log_tenant_time_idx on public.dw_evidence_log(tenant_id,captured_at desc);
create index if not exists dw_evidence_log_source_time_idx on public.dw_evidence_log(source_id,captured_at desc);
create index if not exists dw_evidence_log_hash_idx on public.dw_evidence_log(content_sha256);
create or replace function public.dw_evidence_log_chain_insert()
returns trigger language plpgsql security definer set search_path = pg_catalog, public, extensions
as $$
declare prior_hash text; canonical text;
begin
 perform pg_advisory_xact_lock(732104,881);
 select row_hash into prior_hash from public.dw_evidence_log order by seq desc limit 1;
 new.prev_hash := coalesce(prior_hash,repeat('0',64));
 canonical := concat_ws('|',new.seq::text,new.evidence_id::text,new.tenant_id::text,new.source_id::text,
 coalesce(new.queue_job_id::text,''),new.idempotency_key,new.archive_uri,new.warc_record_id,new.capture_kind,
 coalesce(new.response_status::text,''),new.content_length::text,new.content_sha256,new.archive_sha256,
 new.metadata_sha256,to_char(new.captured_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),new.prev_hash);
 new.row_hash := encode(extensions.digest(convert_to(canonical,'UTF8'),'sha256'),'hex');
 return new;
end $$;
drop trigger if exists dw_evidence_log_chain_before_insert on public.dw_evidence_log;
create trigger dw_evidence_log_chain_before_insert before insert on public.dw_evidence_log for each row execute function public.dw_evidence_log_chain_insert();
create or replace function public.dw_evidence_log_reject_mutation()
returns trigger language plpgsql set search_path = pg_catalog, public
as $$ begin raise exception 'dw_evidence_log is append-only'; end $$;
drop trigger if exists dw_evidence_log_no_update on public.dw_evidence_log;
create trigger dw_evidence_log_no_update before update or delete on public.dw_evidence_log for each row execute function public.dw_evidence_log_reject_mutation();
alter table public.dw_discovery_job_runs add constraint dw_discovery_job_runs_evidence_fk foreign key(evidence_seq) references public.dw_evidence_log(seq) on delete restrict;
create table if not exists public.dw_merkle_anchors (
 id uuid primary key default gen_random_uuid(), from_seq bigint not null, to_seq bigint not null,
 leaf_count integer not null check(leaf_count>0), merkle_root text not null check(merkle_root ~ '^[0-9a-f]{64}$'),
 manifest_sha256 text not null check(manifest_sha256 ~ '^[0-9a-f]{64}$'), manifest_uri text not null,
 ots_proof_uri text, ots_status text not null default 'not_requested' check(ots_status in ('not_requested','pending','confirmed','verification_failed')),
 bitcoin_block_height bigint, anchored_at timestamptz not null default now(),
 check(to_seq>=from_seq), unique(from_seq,to_seq)
);
create table if not exists public.dw_evidence_ots_receipts (
 id uuid primary key default gen_random_uuid(),
 evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 anchor_id uuid references public.dw_merkle_anchors(id) on delete restrict,
 proof_uri text not null, proof_sha256 text not null check(proof_sha256 ~ '^[0-9a-f]{64}
 id uuid primary key default gen_random_uuid(), evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 anchor_id uuid references public.dw_merkle_anchors(id) on delete restrict,
 request_sha256 text not null check(request_sha256 ~ '^[0-9a-f]{64}$'), token_uri text not null,
 token_sha256 text not null check(token_sha256 ~ '^[0-9a-f]{64}$'), serial_number text, policy_oid text,
 signer_fingerprint text, verified boolean not null default false, verification_error text, received_at timestamptz not null default now(),
 check((evidence_seq is null) <> (anchor_id is null))
);
create table if not exists public.dw_sanitized_content (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
 text_content text not null, text_sha256 text not null check(text_sha256 ~ '^[0-9a-f]{64}$'), safe_html text not null,
 sanitizer_name text not null, sanitizer_version text not null,
 extraction_status text not null check(extraction_status in ('ok','empty','unsupported','rejected','error')),
 pdf_scanned boolean not null default false, malware_verdict text not null default 'unknown' check(malware_verdict in ('clean','malicious','unknown','not_applicable')),
 created_at timestamptz not null default now(), unique(evidence_seq,sanitizer_name,sanitizer_version)
);
create index if not exists dw_sanitized_content_text_sha_idx on public.dw_sanitized_content(text_sha256);
create table if not exists public.dw_entities (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete restrict,
 entity_type text not null check(entity_type in ('actor','organization','person','onion','domain','email','btc_address','eth_address','pgp_key','ip','handle','other')),
 canonical_key text, display_name text, confidence double precision not null default 1.0 check(confidence between 0 and 1),
 resolution_state text not null default 'resolved' check(resolution_state in ('resolved','candidate','review_required','rejected')),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index if not exists dw_entities_canonical_key_unique on public.dw_entities(tenant_id,entity_type,canonical_key) where canonical_key is not null;
create table if not exists public.dw_entity_aliases (
 id uuid primary key default gen_random_uuid(), entity_id uuid not null references public.dw_entities(id) on delete restrict,
 alias text not null, normalized_alias text not null, alias_type text not null,
 source_id uuid references public.dw_onion_seeds(id) on delete restrict,
 evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 confidence double precision not null default 1.0 check(confidence between 0 and 1), created_at timestamptz not null default now()
);
create index if not exists dw_entity_aliases_normalized_idx on public.dw_entity_aliases(normalized_alias);
create index if not exists dw_entity_aliases_trgm_idx on public.dw_entity_aliases using gin(normalized_alias extensions.gin_trgm_ops);
create table if not exists public.dw_entity_links (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete restrict,
 from_entity uuid not null references public.dw_entities(id) on delete restrict,
 to_entity uuid not null references public.dw_entities(id) on delete restrict,
 relation text not null check(relation in ('operates','funds','mirrors','mentions','same_as','controls','attributed_to','uses_key','hosts')),
 confidence double precision not null check(confidence between 0 and 1),
 evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 resolution_method text not null check(resolution_method in ('deterministic_anchor','probabilistic','human_review','source_assertion')),
 review_state text not null default 'pending' check(review_state in ('pending','accepted','rejected','retracted')),
 created_at timestamptz not null default now(), check(from_entity<>to_entity), unique(from_entity,to_entity,relation,evidence_seq)
);
create index if not exists dw_entity_links_from_idx on public.dw_entity_links(tenant_id,from_entity,confidence desc);
create index if not exists dw_entity_links_to_idx on public.dw_entity_links(tenant_id,to_entity,confidence desc);
create or replace function public.dw_entity_tenant_guard()
returns trigger language plpgsql security definer set search_path = pg_catalog, public
as $
declare entity_tenant uuid; declare evidence_tenant uuid; declare from_tenant uuid; declare to_tenant uuid;
begin
 if tg_table_name = 'dw_entity_aliases' then
  select tenant_id into entity_tenant from public.dw_entities where id=new.entity_id;
  if new.evidence_seq is not null then select tenant_id into evidence_tenant from public.dw_evidence_log where seq=new.evidence_seq; end if;
  if entity_tenant is null or (evidence_tenant is not null and entity_tenant<>evidence_tenant) then raise exception 'cross-tenant entity alias/evidence reference'; end if;
 elsif tg_table_name = 'dw_entity_mentions' then
  select tenant_id into entity_tenant from public.dw_entities where id=new.entity_id;
  select tenant_id into evidence_tenant from public.dw_evidence_log where seq=new.evidence_seq;
  if entity_tenant is null or evidence_tenant is null or entity_tenant<>evidence_tenant then raise exception 'cross-tenant entity mention/evidence reference'; end if;
 elsif tg_table_name = 'dw_entity_links' then
  select tenant_id into from_tenant from public.dw_entities where id=new.from_entity;
  select tenant_id into to_tenant from public.dw_entities where id=new.to_entity;
  if from_tenant is null or to_tenant is null or from_tenant<>new.tenant_id or to_tenant<>new.tenant_id then raise exception 'cross-tenant entity link'; end if;
  if new.evidence_seq is not null then select tenant_id into evidence_tenant from public.dw_evidence_log where seq=new.evidence_seq; if evidence_tenant is distinct from new.tenant_id then raise exception 'cross-tenant entity link evidence'; end if; end if;
 end if;
 return new;
end $;
drop trigger if exists dw_entity_aliases_tenant_guard on public.dw_entity_aliases;
create trigger dw_entity_aliases_tenant_guard before insert or update on public.dw_entity_aliases for each row execute function public.dw_entity_tenant_guard();
drop trigger if exists dw_entity_links_tenant_guard on public.dw_entity_links;
create trigger dw_entity_links_tenant_guard before insert or update on public.dw_entity_links for each row execute function public.dw_entity_tenant_guard();
create table if not exists public.dw_entity_mentions (
 id uuid primary key default gen_random_uuid(), entity_id uuid not null references public.dw_entities(id) on delete restrict,
 evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict, mention_text text not null,
 char_start integer, char_end integer, resolved_confidence double precision check(resolved_confidence is null or resolved_confidence between 0 and 1),
 model_id text, model_version text, created_at timestamptz not null default now(),
 check(char_start is null or char_start>=0), check(char_end is null or (char_end>=0 and (char_start is null or char_end>=char_start)))
);
drop trigger if exists dw_entity_mentions_tenant_guard on public.dw_entity_mentions;
create trigger dw_entity_mentions_tenant_guard before insert or update on public.dw_entity_mentions for each row execute function public.dw_entity_tenant_guard();
drop trigger if exists dw_entity_mentions_tenant_guard on public.dw_entity_mentions;
create trigger dw_entity_mentions_tenant_guard before insert or update on public.dw_entity_mentions for each row execute function public.dw_entity_tenant_guard();
create table if not exists public.dw_content_translations (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
 source_lang text not null check(source_lang ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'),
 target_lang text not null check(target_lang ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'),
 translated_text text not null, translated_text_sha256 text not null check(translated_text_sha256 ~ '^[0-9a-f]{64}$'),
 model_id text not null, model_version text not null, prompt_or_config_sha256 text,
 translated_at timestamptz not null default now()
);
create table if not exists public.dw_ner_extractions (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
 lang text not null check(lang ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'), model_id text not null, model_version text not null,
 entity_type text not null, mention_text text not null, normalized_value text, char_start integer, char_end integer,
 confidence double precision not null check(confidence between 0 and 1), created_at timestamptz not null default now(),
 check(char_start is null or char_start>=0), check(char_end is null or (char_end>=0 and (char_start is null or char_end>=char_start)))
);
do $$
declare t text;
begin
 foreach t in array array['dw_discovery_job_runs','dw_discovery_dead_letters','dw_source_health','dw_evidence_log','dw_merkle_anchors','dw_evidence_ots_receipts','dw_evidence_tsa_receipts','dw_sanitized_content','dw_entities','dw_entity_aliases','dw_entity_links','dw_entity_mentions','dw_content_translations','dw_ner_extractions'] loop
  execute format('alter table public.%I enable row level security',t);
  execute format('revoke all on table public.%I from public, anon, authenticated',t);
 end loop;
 grant select,insert,update,delete on public.dw_discovery_job_runs,public.dw_discovery_dead_letters,public.dw_source_health to service_role;
 grant select,insert on public.dw_evidence_log,public.dw_evidence_ots_receipts,public.dw_evidence_tsa_receipts to service_role;
 grant select,insert,update on public.dw_merkle_anchors to service_role;
 grant select,insert on public.dw_sanitized_content,public.dw_entities,public.dw_entity_aliases,public.dw_entity_links,public.dw_entity_mentions,public.dw_content_translations,public.dw_ner_extractions to service_role;
 grant usage,select on sequence public.dw_evidence_log_seq_seq to service_role;
end $$;
comment on table public.dw_evidence_log is 'Append-only tenant-scoped WARC evidence manifest with DB-computed hash-chain linkage; external proof verification is a separate state.';
comment on table public.dw_merkle_anchors is 'Periodic Merkle manifests; roots are not externally anchored until proof verification succeeds.';
comment on table public.dw_entity_links is 'Tenant-scoped evidence-linked graph edges; probabilistic matches remain pending until reviewed.';
comment on table public.dw_content_translations is 'Derived translations preserve source evidence and model/version provenance.';
commit;
),
 verification_status text not null check(verification_status in ('pending','confirmed','verification_failed')),
 bitcoin_block_height bigint, verified_at timestamptz, verifier_version text not null,
 created_at timestamptz not null default now(),
 check((evidence_seq is null) <> (anchor_id is null))
);
create table if not exists public.dw_evidence_tsa_receipts (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 anchor_id uuid references public.dw_merkle_anchors(id) on delete restrict,
 request_sha256 text not null check(request_sha256 ~ '^[0-9a-f]{64}$'), token_uri text not null,
 token_sha256 text not null check(token_sha256 ~ '^[0-9a-f]{64}$'), serial_number text, policy_oid text,
 signer_fingerprint text, verified boolean not null default false, verification_error text, received_at timestamptz not null default now(),
 check((evidence_seq is null) <> (anchor_id is null))
);
create table if not exists public.dw_sanitized_content (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
 text_content text not null, text_sha256 text not null check(text_sha256 ~ '^[0-9a-f]{64}$'), safe_html text not null,
 sanitizer_name text not null, sanitizer_version text not null,
 extraction_status text not null check(extraction_status in ('ok','empty','unsupported','rejected','error')),
 pdf_scanned boolean not null default false, malware_verdict text not null default 'unknown' check(malware_verdict in ('clean','malicious','unknown','not_applicable')),
 created_at timestamptz not null default now(), unique(evidence_seq,sanitizer_name,sanitizer_version)
);
create index if not exists dw_sanitized_content_text_sha_idx on public.dw_sanitized_content(text_sha256);
create table if not exists public.dw_entities (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete restrict,
 entity_type text not null check(entity_type in ('actor','organization','person','onion','domain','email','btc_address','eth_address','pgp_key','ip','handle','other')),
 canonical_key text, display_name text, confidence double precision not null default 1.0 check(confidence between 0 and 1),
 resolution_state text not null default 'resolved' check(resolution_state in ('resolved','candidate','review_required','rejected')),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index if not exists dw_entities_canonical_key_unique on public.dw_entities(tenant_id,entity_type,canonical_key) where canonical_key is not null;
create table if not exists public.dw_entity_aliases (
 id uuid primary key default gen_random_uuid(), entity_id uuid not null references public.dw_entities(id) on delete restrict,
 alias text not null, normalized_alias text not null, alias_type text not null,
 source_id uuid references public.dw_onion_seeds(id) on delete restrict,
 evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 confidence double precision not null default 1.0 check(confidence between 0 and 1), created_at timestamptz not null default now()
);
create index if not exists dw_entity_aliases_normalized_idx on public.dw_entity_aliases(normalized_alias);
create index if not exists dw_entity_aliases_trgm_idx on public.dw_entity_aliases using gin(normalized_alias extensions.gin_trgm_ops);
create table if not exists public.dw_entity_links (
 id uuid primary key default gen_random_uuid(), tenant_id uuid not null references public.tenants(id) on delete restrict,
 from_entity uuid not null references public.dw_entities(id) on delete restrict,
 to_entity uuid not null references public.dw_entities(id) on delete restrict,
 relation text not null check(relation in ('operates','funds','mirrors','mentions','same_as','controls','attributed_to','uses_key','hosts')),
 confidence double precision not null check(confidence between 0 and 1),
 evidence_seq bigint references public.dw_evidence_log(seq) on delete restrict,
 resolution_method text not null check(resolution_method in ('deterministic_anchor','probabilistic','human_review','source_assertion')),
 review_state text not null default 'pending' check(review_state in ('pending','accepted','rejected','retracted')),
 created_at timestamptz not null default now(), check(from_entity<>to_entity), unique(from_entity,to_entity,relation,evidence_seq)
);
create index if not exists dw_entity_links_from_idx on public.dw_entity_links(tenant_id,from_entity,confidence desc);
create index if not exists dw_entity_links_to_idx on public.dw_entity_links(tenant_id,to_entity,confidence desc);
create table if not exists public.dw_entity_mentions (
 id uuid primary key default gen_random_uuid(), entity_id uuid not null references public.dw_entities(id) on delete restrict,
 evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict, mention_text text not null,
 char_start integer, char_end integer, resolved_confidence double precision check(resolved_confidence is null or resolved_confidence between 0 and 1),
 model_id text, model_version text, created_at timestamptz not null default now(),
 check(char_start is null or char_start>=0), check(char_end is null or (char_end>=0 and (char_start is null or char_end>=char_start)))
);
create table if not exists public.dw_content_translations (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
 source_lang text not null check(source_lang ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'),
 target_lang text not null check(target_lang ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'),
 translated_text text not null, translated_text_sha256 text not null check(translated_text_sha256 ~ '^[0-9a-f]{64}$'),
 model_id text not null, model_version text not null, prompt_or_config_sha256 text,
 translated_at timestamptz not null default now()
);
create table if not exists public.dw_ner_extractions (
 id uuid primary key default gen_random_uuid(), evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
 lang text not null check(lang ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'), model_id text not null, model_version text not null,
 entity_type text not null, mention_text text not null, normalized_value text, char_start integer, char_end integer,
 confidence double precision not null check(confidence between 0 and 1), created_at timestamptz not null default now(),
 check(char_start is null or char_start>=0), check(char_end is null or (char_end>=0 and (char_start is null or char_end>=char_start)))
);
do $$
declare t text;
begin
 foreach t in array array['dw_discovery_job_runs','dw_discovery_dead_letters','dw_source_health','dw_evidence_log','dw_merkle_anchors','dw_evidence_tsa_receipts','dw_sanitized_content','dw_entities','dw_entity_aliases','dw_entity_links','dw_entity_mentions','dw_content_translations','dw_ner_extractions'] loop
  execute format('alter table public.%I enable row level security',t);
  execute format('revoke all on table public.%I from public, anon, authenticated',t);
 end loop;
 grant select,insert,update,delete on public.dw_discovery_job_runs,public.dw_discovery_dead_letters,public.dw_source_health to service_role;
 grant select,insert on public.dw_evidence_log,public.dw_merkle_anchors,public.dw_evidence_tsa_receipts to service_role;
 grant select,insert on public.dw_sanitized_content,public.dw_entities,public.dw_entity_aliases,public.dw_entity_links,public.dw_entity_mentions,public.dw_content_translations,public.dw_ner_extractions to service_role;
 grant usage,select on sequence public.dw_evidence_log_seq_seq to service_role;
end $$;
comment on table public.dw_evidence_log is 'Append-only tenant-scoped WARC evidence manifest with DB-computed hash-chain linkage; external proof verification is a separate state.';
comment on table public.dw_merkle_anchors is 'Periodic Merkle manifests; roots are not externally anchored until proof verification succeeds.';
comment on table public.dw_entity_links is 'Tenant-scoped evidence-linked graph edges; probabilistic matches remain pending until reviewed.';
comment on table public.dw_content_translations is 'Derived translations preserve source evidence and model/version provenance.';
commit;
