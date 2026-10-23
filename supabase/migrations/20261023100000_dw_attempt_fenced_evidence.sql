-- Cyclothone DW: atomic request-attempt fencing for evidence and source-attempt ledger.
-- Branch-only. Review and validate in an isolated PostgreSQL/Supabase environment before any production migration.
BEGIN;

CREATE OR REPLACE FUNCTION public.record_dw_source_attempt(
  p_source_id text,
  p_status text,
  p_content_sha256 text,
  p_inspected_items integer,
  p_error_code text,
  p_metadata jsonb
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
DECLARE
  v_id bigint;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_source_attempt_service_role_required';
  END IF;
  IF p_status NOT IN ('ok','unavailable','failed','timeout','disabled','historical_only')
     OR p_inspected_items IS NULL OR p_inspected_items < 0
     OR (p_content_sha256 IS NOT NULL AND p_content_sha256 !~ '^[0-9a-f]{64}$')
     OR jsonb_typeof(coalesce(p_metadata, '{}'::jsonb)) <> 'object' THEN
    RAISE EXCEPTION 'dw_source_attempt_invalid_payload';
  END IF;

  INSERT INTO public.dw_source_attempts (
    source_id, status, content_sha256, inspected_items, error_code, metadata
  )
  SELECT s.id, p_status, p_content_sha256, p_inspected_items,
         nullif(left(p_error_code, 100), ''),
         coalesce(p_metadata, '{}'::jsonb)
    FROM public.dw_sources s
   WHERE s.id = p_source_id
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    RAISE EXCEPTION 'dw_source_attempt_unknown_source';
  END IF;
  RETURN v_id;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_source_attempt(text,text,text,integer,text,jsonb)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_attempt(text,text,text,integer,text,jsonb)
  TO service_role;

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
      '[/\?#].*$', ''
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
  IF NOT FOUND OR v_subject.tenant_id <> p_tenant_id
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
