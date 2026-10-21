-- Cyclothone Dark Web trust/isolation foundation. Additive and dormant.
-- No source activation, probing, or secret provisioning is performed by this migration.
begin;
create schema if not exists extensions;
create extension if not exists vector with schema extensions;
create table if not exists public.dw_client_auth_credentials (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references public.tenants(id) on delete cascade,
 onion_hostname text not null check (onion_hostname ~ '^[a-z2-7]{56}\.onion$'),
 encrypted_private_key bytea not null,
 encryption_key_ref text not null,
 key_type text not null default 'x25519' check (key_type='x25519'),
 status text not null default 'provisioned' check (status in ('provisioned','revoked','rotation_required')),
 provisioned_at timestamptz not null default now(), last_used_at timestamptz, revoked_at timestamptz,
 created_by uuid, unique(tenant_id,onion_hostname),
 check(octet_length(encrypted_private_key)>0), check(length(encryption_key_ref) between 1 and 200)
);
create table if not exists public.dw_circuit_assignments (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references public.tenants(id) on delete cascade,
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 isolation_key_digest text not null, tor_instance_ref text not null,
 exit_fingerprint text, request_count integer not null default 0 check(request_count>=0),
 created_at timestamptz not null default now(), rotated_at timestamptz,
 rotation_reason text check(rotation_reason is null or rotation_reason in ('max_requests','manual','suspicion','runtime_reconnect','policy')),
 unique(tenant_id,source_id,isolation_key_digest,tor_instance_ref)
);
create table if not exists public.dw_mirror_integrity (
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 onion_hostname text not null check(onion_hostname ~ '^[a-z2-7]{56}\.onion$'),
 verification_status text not null check(verification_status in ('verified','unsigned','invalid_signature','fingerprint_mismatch','host_not_in_signed_list','verifier_unavailable','malformed_statement')),
 publisher_fingerprint text, pinned_fingerprint text, signed_hosts text[] not null default '{}',
 content_sha256 text not null check(content_sha256 ~ '^[0-9a-f]{64}$'),
 statement_sha256 text check(statement_sha256 is null or statement_sha256 ~ '^[0-9a-f]{64}$'),
 verifier_version text not null, evidence jsonb not null default '{}'::jsonb, fetched_at timestamptz not null default now(),
 check(verification_status <> 'verified' or (publisher_fingerprint is not null and pinned_fingerprint is not null and publisher_fingerprint=pinned_fingerprint and onion_hostname=any(signed_hosts)))
);
create index if not exists dw_mirror_integrity_source_time_idx on public.dw_mirror_integrity(source_id,fetched_at desc);
create table if not exists public.dw_content_fingerprints (
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 content_sha256 text not null check(content_sha256 ~ '^[0-9a-f]{64}$'),
 normalized_text_sha256 text not null check(normalized_text_sha256 ~ '^[0-9a-f]{64}$'),
 minhash_signature integer[] not null, simhash_hex text,
 shingle_size smallint not null default 5 check(shingle_size between 2 and 12),
 algorithm_version text not null, fetched_at timestamptz not null default now(),
 check(cardinality(minhash_signature) between 1 and 256),
 check(simhash_hex is null or simhash_hex ~ '^[0-9a-f]{16}$')
);
create index if not exists dw_content_fingerprints_sha_idx on public.dw_content_fingerprints(content_sha256);
create index if not exists dw_content_fingerprints_norm_sha_idx on public.dw_content_fingerprints(normalized_text_sha256);
create index if not exists dw_content_fingerprints_source_time_idx on public.dw_content_fingerprints(source_id,fetched_at desc);
create table if not exists public.dw_publisher_key_pins (
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 publisher_fingerprint text not null,
 pin_provenance_url text not null,
 pin_provenance_sha256 text not null check(pin_provenance_sha256 ~ '^[0-9a-f]{64}
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 tenant_id uuid references public.tenants(id) on delete cascade, baseline_id uuid,
 algorithm_version text not null, anomaly_score double precision not null check(anomaly_score between 0 and 1),
 signal_types text[] not null default '{}', evidence_sha256 text check(evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
 disposition text not null default 'review' check(disposition in ('review','dismissed','confirmed_change')),
 created_at timestamptz not null default now()
);
create index if not exists dw_source_anomaly_source_time_idx on public.dw_source_anomaly_events(source_id,created_at desc);
create table if not exists public.dw_descriptor_health (
 id uuid primary key default gen_random_uuid(), source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 status text not null check(status in ('ok','not_found','timeout','parse_error','control_unavailable','unsupported','unknown')),
 fetch_latency_ms integer check(fetch_latency_ms is null or fetch_latency_ms>=0),
 fetch_attempts smallint not null default 1 check(fetch_attempts between 1 and 20),
 descriptor_revision integer, introduction_point_count integer check(introduction_point_count is null or introduction_point_count>=0),
 hsdir_fingerprint text, tor_instance_ref text, error_code text,
 evidence jsonb not null default '{}'::jsonb, fetched_at timestamptz not null default now()
);
create index if not exists dw_descriptor_health_source_time_idx on public.dw_descriptor_health(source_id,fetched_at desc);
-- Deception data is kept in independent tables with no relationship to intelligence findings.
create table if not exists public.dw_trust_honeypot_observations (
 id uuid primary key default gen_random_uuid(),
 deployment_id uuid not null references public.dw_honeypot_deployments(id) on delete cascade,
 event_type text not null check(event_type in ('login_attempt','command','file_upload','connection','other')),
 source_ip inet, payload_sha256 text check(payload_sha256 is null or payload_sha256 ~ '^[0-9a-f]{64}$'),
 sanitized_metadata jsonb not null default '{}'::jsonb, observed_at timestamptz not null default now()
);
create index if not exists dw_trust_honeypot_observations_time_idx on public.dw_trust_honeypot_observations(deployment_id,observed_at desc);
create table if not exists public.dw_trust_canary_events (
 id uuid primary key default gen_random_uuid(), provider text not null, provider_event_id text not null,
 token_id_digest text not null, source_hint inet, signature_verified boolean not null default false,
 received_at timestamptz not null default now(), provider_fired_at timestamptz,
 payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
 sanitized_metadata jsonb not null default '{}'::jsonb, unique(provider,provider_event_id),
 check(signature_verified=true)
);
create index if not exists dw_trust_canary_events_time_idx on public.dw_trust_canary_events(received_at desc);
do $$
declare t text;
begin
 foreach t in array array['dw_client_auth_credentials','dw_circuit_assignments','dw_mirror_integrity','dw_publisher_key_pins','dw_content_fingerprints','dw_content_embeddings','dw_source_anomaly_events','dw_descriptor_health','dw_trust_honeypot_observations','dw_trust_canary_events'] loop
  execute format('alter table public.%I enable row level security',t);
  execute format('revoke all on table public.%I from public, anon, authenticated',t);
  execute format('grant select,insert,update,delete on table public.%I to service_role',t);
 end loop;
end $$;
comment on table public.dw_client_auth_credentials is 'Encrypted v3 client-auth material; decryption belongs in a KMS-backed worker.';
comment on table public.dw_circuit_assignments is 'Per-tenant/source isolation metadata; stores no SOCKS password.';
comment on table public.dw_mirror_integrity is 'Mirror verification requires pinned publisher fingerprint and signed-host match.';
comment on table public.dw_source_anomaly_events is 'Anomaly scores are review signals, never findings by themselves.';
comment on table public.dw_trust_honeypot_observations is 'Deception telemetry excluded from intelligence matching.';
comment on table public.dw_trust_canary_events is 'Verified-provider canary telemetry; unsigned events rejected.';
commit;
),
 approval_reference text not null,
 valid_from timestamptz not null default now(), valid_until timestamptz,
 revoked_at timestamptz, created_at timestamptz not null default now(),
 check(valid_until is null or valid_until > valid_from),
 check(revoked_at is null or revoked_at >= valid_from)
);
create index if not exists dw_publisher_key_pins_source_idx on public.dw_publisher_key_pins(source_id,valid_from desc);
create table if not exists public.dw_content_embeddings (
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 tenant_id uuid references public.tenants(id) on delete cascade,
 embedding extensions.vector(1536) not null,
 topic_label text,
 baseline_id uuid,
 model_id text not null,
 algorithm_version text not null,
 anomaly_score double precision check(anomaly_score is null or anomaly_score between 0 and 1),
 content_sha256 text not null check(content_sha256 ~ '^[0-9a-f]{64}
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 tenant_id uuid references public.tenants(id) on delete cascade, baseline_id uuid,
 algorithm_version text not null, anomaly_score double precision not null check(anomaly_score between 0 and 1),
 signal_types text[] not null default '{}', evidence_sha256 text check(evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
 disposition text not null default 'review' check(disposition in ('review','dismissed','confirmed_change')),
 created_at timestamptz not null default now()
);
create index if not exists dw_source_anomaly_source_time_idx on public.dw_source_anomaly_events(source_id,created_at desc);
create table if not exists public.dw_descriptor_health (
 id uuid primary key default gen_random_uuid(), source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 status text not null check(status in ('ok','not_found','timeout','parse_error','control_unavailable','unsupported','unknown')),
 fetch_latency_ms integer check(fetch_latency_ms is null or fetch_latency_ms>=0),
 fetch_attempts smallint not null default 1 check(fetch_attempts between 1 and 20),
 descriptor_revision integer, introduction_point_count integer check(introduction_point_count is null or introduction_point_count>=0),
 hsdir_fingerprint text, tor_instance_ref text, error_code text,
 evidence jsonb not null default '{}'::jsonb, fetched_at timestamptz not null default now()
);
create index if not exists dw_descriptor_health_source_time_idx on public.dw_descriptor_health(source_id,fetched_at desc);
-- Deception data is kept in independent tables with no relationship to intelligence findings.
create table if not exists public.dw_trust_honeypot_observations (
 id uuid primary key default gen_random_uuid(),
 deployment_id uuid not null references public.dw_honeypot_deployments(id) on delete cascade,
 event_type text not null check(event_type in ('login_attempt','command','file_upload','connection','other')),
 source_ip inet, payload_sha256 text check(payload_sha256 is null or payload_sha256 ~ '^[0-9a-f]{64}$'),
 sanitized_metadata jsonb not null default '{}'::jsonb, observed_at timestamptz not null default now()
);
create index if not exists dw_trust_honeypot_observations_time_idx on public.dw_trust_honeypot_observations(deployment_id,observed_at desc);
create table if not exists public.dw_trust_canary_events (
 id uuid primary key default gen_random_uuid(), provider text not null, provider_event_id text not null,
 token_id_digest text not null, source_hint inet, signature_verified boolean not null default false,
 received_at timestamptz not null default now(), provider_fired_at timestamptz,
 payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
 sanitized_metadata jsonb not null default '{}'::jsonb, unique(provider,provider_event_id),
 check(signature_verified=true)
);
create index if not exists dw_trust_canary_events_time_idx on public.dw_trust_canary_events(received_at desc);
do $$
declare t text;
begin
 foreach t in array array['dw_client_auth_credentials','dw_circuit_assignments','dw_mirror_integrity','dw_content_fingerprints','dw_source_anomaly_events','dw_descriptor_health','dw_trust_honeypot_observations','dw_trust_canary_events'] loop
  execute format('alter table public.%I enable row level security',t);
  execute format('revoke all on table public.%I from public, anon, authenticated',t);
  execute format('grant select,insert,update,delete on table public.%I to service_role',t);
 end loop;
end $$;
comment on table public.dw_client_auth_credentials is 'Encrypted v3 client-auth material; decryption belongs in a KMS-backed worker.';
comment on table public.dw_circuit_assignments is 'Per-tenant/source isolation metadata; stores no SOCKS password.';
comment on table public.dw_mirror_integrity is 'Mirror verification requires pinned publisher fingerprint and signed-host match.';
comment on table public.dw_source_anomaly_events is 'Anomaly scores are review signals, never findings by themselves.';
comment on table public.dw_trust_honeypot_observations is 'Deception telemetry excluded from intelligence matching.';
comment on table public.dw_trust_canary_events is 'Verified-provider canary telemetry; unsigned events rejected.';
commit;
),
 created_at timestamptz not null default now()
);
create index if not exists dw_content_embeddings_hnsw_idx on public.dw_content_embeddings using hnsw (embedding extensions.vector_cosine_ops);
create index if not exists dw_content_embeddings_source_time_idx on public.dw_content_embeddings(source_id,created_at desc);
create table if not exists public.dw_source_anomaly_events (
 id uuid primary key default gen_random_uuid(),
 source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 tenant_id uuid references public.tenants(id) on delete cascade, baseline_id uuid,
 algorithm_version text not null, anomaly_score double precision not null check(anomaly_score between 0 and 1),
 signal_types text[] not null default '{}', evidence_sha256 text check(evidence_sha256 is null or evidence_sha256 ~ '^[0-9a-f]{64}$'),
 disposition text not null default 'review' check(disposition in ('review','dismissed','confirmed_change')),
 created_at timestamptz not null default now()
);
create index if not exists dw_source_anomaly_source_time_idx on public.dw_source_anomaly_events(source_id,created_at desc);
create table if not exists public.dw_descriptor_health (
 id uuid primary key default gen_random_uuid(), source_id uuid not null references public.dw_onion_seeds(id) on delete cascade,
 status text not null check(status in ('ok','not_found','timeout','parse_error','control_unavailable','unsupported','unknown')),
 fetch_latency_ms integer check(fetch_latency_ms is null or fetch_latency_ms>=0),
 fetch_attempts smallint not null default 1 check(fetch_attempts between 1 and 20),
 descriptor_revision integer, introduction_point_count integer check(introduction_point_count is null or introduction_point_count>=0),
 hsdir_fingerprint text, tor_instance_ref text, error_code text,
 evidence jsonb not null default '{}'::jsonb, fetched_at timestamptz not null default now()
);
create index if not exists dw_descriptor_health_source_time_idx on public.dw_descriptor_health(source_id,fetched_at desc);
-- Deception data is kept in independent tables with no relationship to intelligence findings.
create table if not exists public.dw_trust_honeypot_observations (
 id uuid primary key default gen_random_uuid(),
 deployment_id uuid not null references public.dw_honeypot_deployments(id) on delete cascade,
 event_type text not null check(event_type in ('login_attempt','command','file_upload','connection','other')),
 source_ip inet, payload_sha256 text check(payload_sha256 is null or payload_sha256 ~ '^[0-9a-f]{64}$'),
 sanitized_metadata jsonb not null default '{}'::jsonb, observed_at timestamptz not null default now()
);
create index if not exists dw_trust_honeypot_observations_time_idx on public.dw_trust_honeypot_observations(deployment_id,observed_at desc);
create table if not exists public.dw_trust_canary_events (
 id uuid primary key default gen_random_uuid(), provider text not null, provider_event_id text not null,
 token_id_digest text not null, source_hint inet, signature_verified boolean not null default false,
 received_at timestamptz not null default now(), provider_fired_at timestamptz,
 payload_sha256 text not null check(payload_sha256 ~ '^[0-9a-f]{64}$'),
 sanitized_metadata jsonb not null default '{}'::jsonb, unique(provider,provider_event_id),
 check(signature_verified=true)
);
create index if not exists dw_trust_canary_events_time_idx on public.dw_trust_canary_events(received_at desc);
do $$
declare t text;
begin
 foreach t in array array['dw_client_auth_credentials','dw_circuit_assignments','dw_mirror_integrity','dw_content_fingerprints','dw_source_anomaly_events','dw_descriptor_health','dw_trust_honeypot_observations','dw_trust_canary_events'] loop
  execute format('alter table public.%I enable row level security',t);
  execute format('revoke all on table public.%I from public, anon, authenticated',t);
  execute format('grant select,insert,update,delete on table public.%I to service_role',t);
 end loop;
end $$;
comment on table public.dw_client_auth_credentials is 'Encrypted v3 client-auth material; decryption belongs in a KMS-backed worker.';
comment on table public.dw_circuit_assignments is 'Per-tenant/source isolation metadata; stores no SOCKS password.';
comment on table public.dw_mirror_integrity is 'Mirror verification requires pinned publisher fingerprint and signed-host match.';
comment on table public.dw_source_anomaly_events is 'Anomaly scores are review signals, never findings by themselves.';
comment on table public.dw_trust_honeypot_observations is 'Deception telemetry excluded from intelligence matching.';
comment on table public.dw_trust_canary_events is 'Verified-provider canary telemetry; unsigned events rejected.';
commit;
