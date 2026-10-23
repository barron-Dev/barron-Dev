-- Proof-bound probe RPC. Requires PR #76 foundations and a documented, known-good base.
-- Proof rows are intentionally not writable by service_role until a trusted verifier writer exists.
begin;

create table if not exists public.dw_tor_route_proofs (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references public.dw_onion_seeds(id) on delete restrict,
  request_url text not null,
  route_verified boolean not null default false,
  descriptor_revision integer,
  hsdir_fingerprint text,
  rp_fingerprint text,
  tor_instance_ref text not null,
  proof_sha256 text not null check (proof_sha256 ~ '^[0-9a-f]{64}$'),
  verifier_version text not null,
  observed_at timestamptz not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  check (expires_at > observed_at)
);

create table if not exists public.dw_publisher_proofs (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references public.dw_onion_seeds(id) on delete restrict,
  mirror_integrity_id uuid not null references public.dw_mirror_integrity(id) on delete restrict,
  proof_url text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  publisher_fingerprint text not null,
  pinned_fingerprint text not null,
  signed_hosts text[] not null,
  verification_status text not null check (verification_status in ('verified','invalid_signature','fingerprint_mismatch','host_not_in_signed_list','verifier_unavailable')),
  proof_sha256 text not null check (proof_sha256 ~ '^[0-9a-f]{64}$'),
  verifier_version text not null,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  check (verification_status <> 'verified' or
         (publisher_fingerprint = pinned_fingerprint and verified_at is not null))
);

create table if not exists public.dw_corroboration_proofs (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references public.dw_onion_seeds(id) on delete restrict,
  evidence_seq bigint not null references public.dw_evidence_log(seq) on delete restrict,
  anchor_id uuid not null references public.dw_merkle_anchors(id) on delete restrict,
  independent_source_url text not null,
  independent_source_sha256 text not null check (independent_source_sha256 ~ '^[0-9a-f]{64}$'),
  verification_status text not null check (verification_status in ('verified','pending','failed','invalid','unavailable')),
  proof_sha256 text not null check (proof_sha256 ~ '^[0-9a-f]{64}$'),
  verifier_version text not null,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  check (verification_status <> 'verified' or verified_at is not null)
);

-- Register the new proof tables before policy enforcement.
insert into public.dw_table_security_policy(tablename, append_only, grants_to_service_role, notes)
values
 ('dw_tor_route_proofs', true, array['SELECT'], 'Trusted Tor verifier output; app role cannot write attestations'),
 ('dw_publisher_proofs', true, array['SELECT'], 'Trusted publisher signature verifier output'),
 ('dw_corroboration_proofs', true, array['SELECT'], 'Independent-source corroboration tied to captured evidence and anchor')
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
     and (t.tablename like 'dw\_%evidence%' escape '\'
       or t.tablename like 'dw\_%proofs' escape '\')
     and not exists (
       select 1 from public.dw_table_security_policy p where p.tablename = t.tablename
     );
  if unregistered is not null then
    raise exception 'unregistered evidence/proof tables; add an explicit policy first: %', unregistered;
  end if;
end $$;

do $$
declare r record;
begin
  for r in select * from public.dw_table_security_policy order by tablename loop
    execute format('alter table public.%I enable row level security', r.tablename);
    execute format('revoke all on table public.%I from public, anon, authenticated', r.tablename);
    execute format('revoke all on table public.%I from service_role', r.tablename);
    execute format(
      'grant %s on table public.%I to service_role',
      array_to_string(r.grants_to_service_role, ', '), r.tablename
    );
    if r.append_only then
      execute format('revoke update, delete on table public.%I from service_role', r.tablename);
      execute format('drop trigger if exists %I on public.%I', r.tablename || '_policy_no_mutate', r.tablename);
      execute format(
        'create trigger %I before update or delete on public.%I for each row execute function public.dw_block_mutation()',
        r.tablename || '_policy_no_mutate', r.tablename
      );
    end if;
  end loop;
end $$;

-- Remove the caller-attestation RPC from application roles. Keep the legacy function
-- for administrative rollback only; it is no longer callable by API/worker roles.
revoke execute on function public.dw_record_onion_probe_result(
  uuid, text, boolean, text, integer, text, text, bigint, text, boolean, text, boolean, boolean, text, text, jsonb
) from public, anon, authenticated, service_role;
drop function if exists public.dw_record_onion_probe_result(
  uuid, text, boolean, text, integer, text, text, bigint, text, boolean, text, boolean, boolean, text, text, jsonb
);

create or replace function public.dw_record_onion_probe_result(
  p_seed_id uuid,
  p_probe_method text,
  p_tor_route_proof_id uuid,
  p_request_url text,
  p_http_status integer,
  p_response_sha256 text,
  p_content_type text,
  p_response_bytes bigint,
  p_publisher_proof_id uuid,
  p_corroboration_proof_id uuid,
  p_evidence_seq bigint,
  p_outcome text,
  p_error_code text default null,
  p_evidence_metadata jsonb default '{}'::jsonb
)
returns bigint
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  v_seed public.dw_onion_seeds%rowtype;
  v_route public.dw_tor_route_proofs%rowtype;
  v_publisher public.dw_publisher_proofs%rowtype;
  v_corroboration public.dw_corroboration_proofs%rowtype;
  v_evidence public.dw_evidence_log%rowtype;
  v_anchor public.dw_merkle_anchors%rowtype;
  v_id bigint;
  v_tor_verified boolean := false;
  v_publisher_verified boolean := false;
  v_corroboration_verified boolean := false;
  v_provenance_match boolean := false;
begin
  if p_evidence_metadata is null or jsonb_typeof(p_evidence_metadata) <> 'object' then
    raise exception 'evidence metadata must be a JSON object' using errcode='22023';
  end if;

  select * into v_seed
    from public.dw_onion_seeds
   where id = p_seed_id
   for update;
  if not found then raise exception 'seed not found' using errcode='P0002'; end if;
  if v_seed.hostname is null or v_seed.hostname !~ '^[a-z2-7]{56}\.onion$' then
    raise exception 'seed hostname is not a valid v3 onion hostname' using errcode='22023';
  end if;
  if p_request_url is null
     or lower(regexp_replace(p_request_url, '^https?://([^/]+).*$','\1')) <> lower(v_seed.hostname) then
    raise exception 'probe URL host must exactly match registered seed hostname' using errcode='22023';
  end if;

  if p_tor_route_proof_id is not null then
    select * into v_route
      from public.dw_tor_route_proofs
     where id = p_tor_route_proof_id
       and source_id = p_seed_id
       and request_url = p_request_url
       and route_verified = true
       and observed_at <= now()
       and expires_at > now()
     for share;
    if not found then
      raise exception 'verified Tor route proof missing, expired, or bound to another source/request' using errcode='42501';
    end if;
    v_tor_verified := true;
  end if;

  if p_publisher_proof_id is not null then
    select * into v_publisher
      from public.dw_publisher_proofs
     where id = p_publisher_proof_id
       and source_id = p_seed_id
       and content_sha256 = p_response_sha256
       and verification_status = 'verified'
       and publisher_fingerprint = pinned_fingerprint
       and lower(v_seed.hostname) = any (select lower(host.value) from unnest(signed_hosts) as host(value))
       and verified_at is not null
     for share;
    if not found then
      raise exception 'verified publisher proof missing or mismatched to source/content' using errcode='42501';
    end if;
    if not exists (
      select 1 from public.dw_mirror_integrity mi
       where mi.id = v_publisher.mirror_integrity_id
         and mi.source_id = p_seed_id
         and mi.verification_status = 'verified'
         and mi.publisher_fingerprint = v_publisher.publisher_fingerprint
         and mi.pinned_fingerprint = v_publisher.pinned_fingerprint
         and mi.content_sha256 = p_response_sha256
         and lower(v_seed.hostname) = any (select lower(host.value) from unnest(mi.signed_hosts) as host(value))
    ) then
      raise exception 'publisher proof is not backed by a matching verified mirror-integrity record' using errcode='42501';
    end if;
    v_publisher_verified := true;
  end if;

  if p_evidence_seq is not null then
    select * into v_evidence
      from public.dw_evidence_log
     where seq = p_evidence_seq and source_id = p_seed_id
     for share;
    if not found then
      raise exception 'evidence sequence does not belong to this source' using errcode='42501';
    end if;
    v_provenance_match := true;
  end if;

  if p_corroboration_proof_id is not null then
    select * into v_corroboration
      from public.dw_corroboration_proofs
     where id = p_corroboration_proof_id
       and source_id = p_seed_id
       and evidence_seq = p_evidence_seq
       and verification_status = 'verified'
       and verified_at is not null
     for share;
    if not found then
      raise exception 'independent corroboration proof missing or mismatched to source/evidence' using errcode='42501';
    end if;
    if lower(regexp_replace(v_corroboration.independent_source_url, '^https?://([^/:]+).*$', '\\1')) = lower(v_seed.hostname)
       or lower(v_corroboration.independent_source_url) = lower(p_request_url) then
      raise exception 'corroboration source is not independent of the onion target' using errcode='22023';
    end if;
    select * into v_anchor
      from public.dw_merkle_anchors
     where id = v_corroboration.anchor_id
       and p_evidence_seq between from_seq and to_seq
       and ots_status = 'confirmed'
     for share;
    if not found then
      raise exception 'corroboration anchor is missing, unconfirmed, or outside the evidence range' using errcode='42501';
    end if;
    if not exists (
      select 1 from public.dw_evidence_ots_receipts r
       where r.anchor_id = v_corroboration.anchor_id
         and r.evidence_seq = p_evidence_seq
         and r.state = 'confirmed'
         and r.bitcoin_block_height is not null
    ) then
      raise exception 'corroboration anchor lacks a confirmed OTS receipt for this evidence' using errcode='42501';
    end if;
    v_corroboration_verified := true;
  end if;

  if p_outcome = 'verified_publisher' then
    if p_tor_route_proof_id is null or p_publisher_proof_id is null
       or p_corroboration_proof_id is null or p_evidence_seq is null
       or not v_tor_verified or not v_publisher_verified
       or not v_corroboration_verified or not v_provenance_match
       or p_http_status is null or p_http_status < 200 or p_http_status >= 300
       or p_response_sha256 is null or p_response_sha256 !~ '^[0-9a-f]{64}$' then
      raise exception 'verified_publisher requires valid route, publisher, corroboration, evidence, HTTP and content-hash proofs' using errcode='22023';
    end if;
    if v_seed.seed_type not in ('publisher_onion') then
      raise exception 'only publisher_onion seeds can be activated as publisher collectors' using errcode='22023';
    end if;
  end if;

  insert into public.dw_onion_probe_evidence(
    seed_id,probe_method,tor_route_verified,request_url,http_status,response_sha256,content_type,response_bytes,
    publisher_proof_url,publisher_proof_verified,independent_corroboration_url,independent_corroboration_verified,
    provenance_match,outcome,error_code,evidence_metadata
  ) values (
    p_seed_id,p_probe_method,v_tor_verified,p_request_url,p_http_status,p_response_sha256,p_content_type,p_response_bytes,
    case when v_publisher_verified then v_publisher.proof_url else null end,
    v_publisher_verified,
    case when v_corroboration_verified then v_corroboration.independent_source_url else null end,
    v_corroboration_verified,v_provenance_match,p_outcome,p_error_code,p_evidence_metadata
  ) returning id into v_id;

  update public.dw_onion_seeds set
    last_checked = now(),
    last_status = case when p_outcome='verified_publisher' then 'checked'
                       when p_outcome='unreachable' then 'unreachable'
                       when p_outcome='provenance_mismatch' then 'provenance_mismatch'
                       else 'reachable_unverified' end,
    last_http_status = p_http_status,
    last_response_sha256 = p_response_sha256,
    content_type = p_content_type,
    status = case when p_outcome='verified_publisher' then 'checked'
                  when p_outcome='unreachable' then 'failed' else 'candidate' end,
    candidate_trust = case when p_outcome='verified_publisher' then 'verified' else 'candidate' end,
    monitoring_enabled = (p_outcome='verified_publisher'),
    probe_metadata = coalesce(probe_metadata,'{}'::jsonb) || p_evidence_metadata ||
      jsonb_build_object('reachability_verified',v_tor_verified and p_http_status between 200 and 299,
                         'publisher_identity_verified',v_publisher_verified,
                         'last_probe_evidence_id',v_id,'probe_outcome',p_outcome,
                         'provenance_match',v_provenance_match),
    updated_at = now()
  where id = p_seed_id;

  insert into public.dw_source_health_events(source_key,event_type,outcome,http_status,response_sha256,metadata,customer_finding_created)
  values (
    v_seed.hostname,
    case when p_outcome='verified_publisher' then 'probe_succeeded'
         when p_outcome='unreachable' then 'probe_failed'
         when p_outcome='provenance_mismatch' then 'provenance_mismatch'
         else 'source_unavailable' end,
    case when p_outcome='verified_publisher' then 'success'
         when p_outcome='unreachable' then 'failed'
         when p_outcome='provenance_mismatch' then 'blocked'
         else 'unknown' end,
    p_http_status,p_response_sha256,
    jsonb_build_object('probe_evidence_id',v_id,'seed_type',v_seed.seed_type,'outcome',p_outcome),
    false
  );
  return v_id;
end;
$$;

revoke all on function public.dw_record_onion_probe_result(
  uuid, text, uuid, text, integer, text, text, bigint, uuid, uuid, bigint, text, text, jsonb
) from public, anon, authenticated;
grant execute on function public.dw_record_onion_probe_result(
  uuid, text, uuid, text, integer, text, text, bigint, uuid, uuid, bigint, text, text, jsonb
) to service_role;

commit;
