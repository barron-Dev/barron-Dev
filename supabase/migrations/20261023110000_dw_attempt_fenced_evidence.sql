-- Cyclothone DW: atomic request-attempt fencing for evidence and source-attempt ledger.
-- Branch-only. Review and validate in an isolated PostgreSQL/Supabase environment before any production migration.
BEGIN;

ALTER TABLE public.dw_source_attempts
  ADD COLUMN IF NOT EXISTS service_request_id uuid REFERENCES public.service_requests(id),
  ADD COLUMN IF NOT EXISTS expected_attempt integer;

-- Remove older writer overloads so they cannot create unbound ledger rows.
DROP FUNCTION IF EXISTS public.record_dw_source_attempt(text,text,text,integer,text,jsonb);
DROP FUNCTION IF EXISTS public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean
);

CREATE OR REPLACE FUNCTION public.record_dw_source_attempt(
  p_source_id text,
  p_status text,
  p_content_sha256 text,
  p_inspected_items integer,
  p_error_code text,
  p_metadata jsonb,
  p_route_verified boolean,
  p_hs_desc_content_received boolean,
  p_descriptor_fetched boolean,
  p_rendezvous_hop_verified boolean,
  p_stream_circuit_bound boolean,
  p_auth_ok boolean
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_id bigint;
  v_request public.service_requests;
  v_request_id uuid;
  v_expected_attempt integer;
  v_seed jsonb;
  v_seed_proofs jsonb;
  v_has_protocol_proof boolean := false;
  v_any_tor_claim boolean;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_source_attempt_service_role_required';
  END IF;
  IF p_status NOT IN ('ok','unavailable','failed','timeout','disabled','historical_only')
     OR p_inspected_items IS NULL OR p_inspected_items < 0
     OR (p_content_sha256 IS NOT NULL AND p_content_sha256 !~ '^[0-9a-f]{64}
$function$;

REVOKE ALL ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) TO service_role;

-- This wrapper locks the request row and validates the active attempt in the
-- same transaction that inserts trust evidence. A Python pre-check alone is
-- not a fencing boundary: the lease could be reclaimed between check and RPC.
CREATE OR REPLACE FUNCTION public.dw_record_evidence_if_current_attempt(
  p_service_request_id uuid,
  p_expected_attempt integer,
  p_tenant_id uuid,
  p_watchlist_id uuid,
  p_subject_id uuid,
  p_evidence_type text,
  p_source_type text,
  p_source_id text,
  p_content_type text,
  p_content_uri text,
  p_content_hash text,
  p_collected_at timestamptz,
  p_expires_at timestamptz,
  p_signature_algorithm text,
  p_signer_key_id text,
  p_signature text,
  p_metadata jsonb
) RETURNS public.trust_evidence
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_request public.service_requests;
  v_org_tenant uuid;
  v_watch public.dw_watchlist;
  v_subject public.trust_subjects;
  v_evidence public.trust_evidence;
  v_expected_kind text;
  v_request_value text;
  v_watch_value text;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_evidence_service_role_required';
  END IF;

  -- The privileged writer may only register bounded, read-back-verified
  -- native-onion candidate evidence. It cannot mint verified findings.
  IF p_evidence_type IS DISTINCT FROM 'dark_web_page_match'
     OR p_source_type IS DISTINCT FROM 'native_onion'
     OR p_content_type IS DISTINCT FROM 'text/plain'
     OR p_content_uri !~ '^supabase://dw-evidence-private/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$'
     OR p_content_hash IS NULL
     OR p_content_hash !~ '^[0-9a-f]{64}$'
     OR p_source_id !~ '^https?://[a-z2-7]{56}\.onion(:(80|443))?(/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$'
     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;

     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;
)
     OR jsonb_typeof(coalesce(p_metadata, '{}'::jsonb)) <> 'object' THEN
    RAISE EXCEPTION 'dw_source_attempt_invalid_payload';
  END IF;
  BEGIN
    v_request_id := nullif(p_metadata->>'request_id', '')::uuid;
    v_expected_attempt := nullif(p_metadata->>'expected_attempt', '')::integer;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'dw_source_attempt_request_binding_missing';
  END;
  IF v_request_id IS NULL OR v_expected_attempt IS NULL OR v_expected_attempt < 1 THEN
    RAISE EXCEPTION 'dw_source_attempt_request_binding_missing';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = v_request_id
   FOR UPDATE;
  IF NOT FOUND
     OR v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> v_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_source_attempt_current_lease_rejected';
  END IF;

  v_any_tor_claim := coalesce(p_route_verified, false)
    OR coalesce(p_hs_desc_content_received, false)
    OR coalesce(p_descriptor_fetched, false)
    OR coalesce(p_rendezvous_hop_verified, false)
    OR coalesce(p_stream_circuit_bound, false)
    OR coalesce(p_auth_ok, false);

  IF p_source_id <> 'native_onion' AND v_any_tor_claim THEN
    RAISE EXCEPTION 'dw_source_attempt_tor_claim_on_non_tor_source';
  END IF;
  IF p_source_id = 'native_onion' AND v_any_tor_claim THEN
    v_seed_proofs := p_metadata->'tor_protocol_evidence'->'seed_proofs';
    IF jsonb_typeof(v_seed_proofs) IS DISTINCT FROM 'array'
       OR jsonb_array_length(v_seed_proofs) = 0 THEN
      RAISE EXCEPTION 'dw_source_attempt_tor_proof_bundle_missing';
    END IF;
    FOR v_seed IN SELECT value FROM jsonb_array_elements(v_seed_proofs)
    LOOP
      IF coalesce(v_seed->>'service_request_id', '') <> v_request_id::text
         OR coalesce(v_seed->>'content_sha256', '') !~ '^[0-9a-f]{64}
$function$;

REVOKE ALL ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) TO service_role;

-- This wrapper locks the request row and validates the active attempt in the
-- same transaction that inserts trust evidence. A Python pre-check alone is
-- not a fencing boundary: the lease could be reclaimed between check and RPC.
CREATE OR REPLACE FUNCTION public.dw_record_evidence_if_current_attempt(
  p_service_request_id uuid,
  p_expected_attempt integer,
  p_tenant_id uuid,
  p_watchlist_id uuid,
  p_subject_id uuid,
  p_evidence_type text,
  p_source_type text,
  p_source_id text,
  p_content_type text,
  p_content_uri text,
  p_content_hash text,
  p_collected_at timestamptz,
  p_expires_at timestamptz,
  p_signature_algorithm text,
  p_signer_key_id text,
  p_signature text,
  p_metadata jsonb
) RETURNS public.trust_evidence
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_request public.service_requests;
  v_org_tenant uuid;
  v_watch public.dw_watchlist;
  v_subject public.trust_subjects;
  v_evidence public.trust_evidence;
  v_expected_kind text;
  v_request_value text;
  v_watch_value text;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_evidence_service_role_required';
  END IF;

  -- The privileged writer may only register bounded, read-back-verified
  -- native-onion candidate evidence. It cannot mint verified findings.
  IF p_evidence_type IS DISTINCT FROM 'dark_web_page_match'
     OR p_source_type IS DISTINCT FROM 'native_onion'
     OR p_content_type IS DISTINCT FROM 'text/plain'
     OR p_content_uri !~ '^supabase://dw-evidence-private/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$'
     OR p_content_hash IS NULL
     OR p_content_hash !~ '^[0-9a-f]{64}$'
     OR p_source_id !~ '^https?://[a-z2-7]{56}\.onion(:(80|443))?(/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$'
     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;

     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;

         OR coalesce(v_seed->>'descriptor_sha256', '') !~ '^[0-9a-f]{64}
$function$;

REVOKE ALL ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) TO service_role;

-- This wrapper locks the request row and validates the active attempt in the
-- same transaction that inserts trust evidence. A Python pre-check alone is
-- not a fencing boundary: the lease could be reclaimed between check and RPC.
CREATE OR REPLACE FUNCTION public.dw_record_evidence_if_current_attempt(
  p_service_request_id uuid,
  p_expected_attempt integer,
  p_tenant_id uuid,
  p_watchlist_id uuid,
  p_subject_id uuid,
  p_evidence_type text,
  p_source_type text,
  p_source_id text,
  p_content_type text,
  p_content_uri text,
  p_content_hash text,
  p_collected_at timestamptz,
  p_expires_at timestamptz,
  p_signature_algorithm text,
  p_signer_key_id text,
  p_signature text,
  p_metadata jsonb
) RETURNS public.trust_evidence
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_request public.service_requests;
  v_org_tenant uuid;
  v_watch public.dw_watchlist;
  v_subject public.trust_subjects;
  v_evidence public.trust_evidence;
  v_expected_kind text;
  v_request_value text;
  v_watch_value text;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_evidence_service_role_required';
  END IF;

  -- The privileged writer may only register bounded, read-back-verified
  -- native-onion candidate evidence. It cannot mint verified findings.
  IF p_evidence_type IS DISTINCT FROM 'dark_web_page_match'
     OR p_source_type IS DISTINCT FROM 'native_onion'
     OR p_content_type IS DISTINCT FROM 'text/plain'
     OR p_content_uri !~ '^supabase://dw-evidence-private/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$'
     OR p_content_hash IS NULL
     OR p_content_hash !~ '^[0-9a-f]{64}$'
     OR p_source_id !~ '^https?://[a-z2-7]{56}\.onion(:(80|443))?(/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$'
     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;

     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;

         OR coalesce(v_seed->'proof'->>'route_verified', 'false') <> 'true'
         OR coalesce(v_seed->'proof'->>'hs_desc_content_received', 'false') <> 'true'
         OR coalesce(v_seed->'proof'->>'descriptor_fetched', 'false') <> 'true'
         OR coalesce(v_seed->'proof'->>'rendezvous_hop_verified', 'false') <> 'true'
         OR coalesce(v_seed->'proof'->>'stream_circuit_bound', 'false') <> 'true'
         OR coalesce(v_seed->'control_assertions'->>'tor_control_authenticated', 'false') <> 'true'
         OR coalesce(v_seed->'control_assertions'->>'tor_bootstrap_complete', 'false') <> 'true'
         OR coalesce(v_seed->'control_assertions'->>'tor_socks_auth_isolation_configured', 'false') <> 'true'
         OR coalesce(v_seed->'control_assertions'->>'hsfetch_accepted', 'false') <> 'true'
         OR coalesce(v_seed->>'socks_auth_bound', 'false') <> 'true' THEN
        RAISE EXCEPTION 'dw_source_attempt_tor_proof_bundle_invalid';
      END IF;
    END LOOP;
    IF NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(v_seed_proofs) AS proof
       WHERE proof->>'content_sha256' = lower(coalesce(p_content_sha256, ''))
    ) THEN
      RAISE EXCEPTION 'dw_source_attempt_content_digest_not_bound';
    END IF;
    v_has_protocol_proof := true;
  END IF;
  IF p_source_id = 'native_onion' AND p_status = 'ok'
     AND (NOT v_has_protocol_proof OR p_inspected_items <= 0
          OR p_content_sha256 IS NULL
          OR NOT coalesce(p_route_verified, false)
          OR NOT coalesce(p_hs_desc_content_received, false)
          OR NOT coalesce(p_descriptor_fetched, false)
          OR NOT coalesce(p_rendezvous_hop_verified, false)
          OR NOT coalesce(p_stream_circuit_bound, false)
          OR NOT coalesce(p_auth_ok, false)) THEN
    RAISE EXCEPTION 'dw_source_attempt_native_onion_success_unproven';
  END IF;

  INSERT INTO public.dw_source_attempts (
    service_request_id, expected_attempt, source_id, status, content_sha256,
    inspected_items, error_code, metadata, route_verified,
    hs_desc_content_received, descriptor_fetched, rendezvous_hop_verified,
    stream_circuit_bound, auth_ok
  )
  SELECT v_request_id, v_expected_attempt, s.id, p_status, p_content_sha256,
         p_inspected_items, nullif(left(p_error_code, 100), ''),
         coalesce(p_metadata, '{}'::jsonb),
         coalesce(p_route_verified, false) AND v_has_protocol_proof,
         coalesce(p_hs_desc_content_received, false) AND v_has_protocol_proof,
         coalesce(p_descriptor_fetched, false) AND v_has_protocol_proof,
         coalesce(p_rendezvous_hop_verified, false) AND v_has_protocol_proof,
         coalesce(p_stream_circuit_bound, false) AND v_has_protocol_proof,
         coalesce(p_auth_ok, false) AND v_has_protocol_proof
    FROM public.dw_sources s
   WHERE s.id = p_source_id
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    RAISE EXCEPTION 'dw_source_attempt_unknown_source';
  END IF;
  RETURN v_id;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_attempt(
  text,text,text,integer,text,jsonb,boolean,boolean,boolean,boolean,boolean,boolean
) TO service_role;

-- This wrapper locks the request row and validates the active attempt in the
-- same transaction that inserts trust evidence. A Python pre-check alone is
-- not a fencing boundary: the lease could be reclaimed between check and RPC.
CREATE OR REPLACE FUNCTION public.dw_record_evidence_if_current_attempt(
  p_service_request_id uuid,
  p_expected_attempt integer,
  p_tenant_id uuid,
  p_watchlist_id uuid,
  p_subject_id uuid,
  p_evidence_type text,
  p_source_type text,
  p_source_id text,
  p_content_type text,
  p_content_uri text,
  p_content_hash text,
  p_collected_at timestamptz,
  p_expires_at timestamptz,
  p_signature_algorithm text,
  p_signer_key_id text,
  p_signature text,
  p_metadata jsonb
) RETURNS public.trust_evidence
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_request public.service_requests;
  v_org_tenant uuid;
  v_watch public.dw_watchlist;
  v_subject public.trust_subjects;
  v_evidence public.trust_evidence;
  v_expected_kind text;
  v_request_value text;
  v_watch_value text;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_evidence_service_role_required';
  END IF;

  -- The privileged writer may only register bounded, read-back-verified
  -- native-onion candidate evidence. It cannot mint verified findings.
  IF p_evidence_type IS DISTINCT FROM 'dark_web_page_match'
     OR p_source_type IS DISTINCT FROM 'native_onion'
     OR p_content_type IS DISTINCT FROM 'text/plain'
     OR p_content_uri !~ '^supabase://dw-evidence-private/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$'
     OR p_content_hash IS NULL
     OR p_content_hash !~ '^[0-9a-f]{64}$'
     OR p_source_id !~ '^https?://[a-z2-7]{56}\.onion(:(80|443))?(/[A-Za-z0-9._~!$&()*+,;=:@%/-]*)?$'
     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;

     OR coalesce(p_metadata->>'readback_sha256_verified', 'false') <> 'true'
     OR coalesce(p_metadata->>'classification', '') <> 'candidate_evidence_not_verified'
     OR coalesce(p_metadata->>'service_request_id', '') <> p_service_request_id::text
     OR coalesce(p_metadata->>'tenant_id', '') <> p_tenant_id::text
     OR coalesce(p_metadata->>'watchlist_id', '') <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_payload_policy_rejected';
  END IF;

  SELECT * INTO v_request
    FROM public.service_requests
   WHERE id = p_service_request_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;
  IF v_request.service_key <> 'dark_web_monitoring'
     OR v_request.processing_state <> 'running'
     OR v_request.attempts <> p_expected_attempt
     OR v_request.locked_until IS NULL
     OR v_request.locked_until <= clock_timestamp() THEN
    RAISE EXCEPTION 'dw_evidence_attempt_fence_rejected';
  END IF;

  SELECT tenant_id INTO v_org_tenant
    FROM public.customer_organizations
   WHERE id = v_request.organization_id;
  IF v_org_tenant IS NULL OR v_org_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'dw_evidence_tenant_fence_rejected';
  END IF;

  SELECT * INTO v_watch
    FROM public.dw_watchlist
   WHERE id = p_watchlist_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'dw_evidence_watchlist_fence_rejected';
  END IF;

  v_expected_kind := CASE lower(coalesce(v_request.target_type, ''))
    WHEN 'domain' THEN 'domain'
    WHEN 'url' THEN 'domain'
    WHEN 'email' THEN 'email'
    WHEN 'brand' THEN 'company_name'
    WHEN 'username' THEN 'username'
    WHEN 'ip' THEN 'ip'
    WHEN 'other' THEN 'other'
    ELSE NULL
  END;
  IF lower(coalesce(v_request.target_type, '')) IN ('domain','url') THEN
    v_request_value := lower(regexp_replace(
      regexp_replace(trim(coalesce(v_request.target, '')), '^https?://', '', 'i'),
      '[/#?].*$', ''
    ));
    v_request_value := regexp_replace(v_request_value, ':[0-9]+$', '');
    v_request_value := rtrim(v_request_value, '.');
  ELSE
    v_request_value := lower(trim(coalesce(v_request.target, '')));
  END IF;
  v_watch_value := lower(trim(coalesce(v_watch.value, '')));
  IF v_expected_kind IS NULL OR v_watch.kind <> v_expected_kind
     OR v_watch_value <> v_request_value THEN
    RAISE EXCEPTION 'dw_evidence_target_fence_rejected';
  END IF;

  SELECT * INTO v_subject
    FROM public.trust_subjects
   WHERE id = p_subject_id
   FOR SHARE;
  IF NOT FOUND OR v_subject.tenant_id IS NULL
     OR v_subject.tenant_id <> p_tenant_id
     OR v_subject.subject_kind <> 'dark_web_monitoring_target'
     OR v_subject.external_ref <> p_watchlist_id::text THEN
    RAISE EXCEPTION 'dw_evidence_subject_fence_rejected';
  END IF;

  v_evidence := public.trust_record_evidence(
    p_subject_id, p_evidence_type, p_source_type, p_source_id,
    p_content_type, p_content_uri, p_content_hash, p_collected_at,
    p_expires_at, p_signature_algorithm, p_signer_key_id, p_signature,
    coalesce(p_metadata, '{}'::jsonb)
  );
  IF v_evidence.tenant_id <> p_tenant_id
     OR v_evidence.subject_id <> p_subject_id
     OR v_evidence.content_uri <> p_content_uri
     OR v_evidence.content_hash <> p_content_hash
     OR v_evidence.source_id <> p_source_id THEN
    RAISE EXCEPTION 'dw_evidence_return_binding_failed';
  END IF;
  RETURN v_evidence;
END;
$function$;

REVOKE ALL ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dw_record_evidence_if_current_attempt(
  uuid,integer,uuid,uuid,uuid,text,text,text,text,text,text,timestamptz,timestamptz,text,text,text,jsonb
) TO service_role;

COMMIT;
