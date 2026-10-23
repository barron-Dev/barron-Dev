-- Branch-only source-attempt writer. Do not apply to production without release approval.
-- The RPC records operational outcomes but deliberately cannot certify Tor/onion
-- protocol proofs that the collector does not currently produce.
BEGIN;

CREATE OR REPLACE FUNCTION public.record_dw_source_attempt(
  p_source_id text,
  p_status text,
  p_content_sha256 text DEFAULT NULL,
  p_inspected_items integer DEFAULT 0,
  p_error_code text DEFAULT NULL,
  p_metadata jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $function$
DECLARE
  v_id bigint;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'dw_source_attempt_service_role_required'
      USING ERRCODE = '42501';
  END IF;
  IF p_source_id IS NULL OR length(trim(p_source_id)) = 0
     OR p_status NOT IN ('ok','unavailable','failed','timeout','disabled','historical_only')
     OR p_inspected_items IS NULL OR p_inspected_items < 0
     OR (p_content_sha256 IS NOT NULL AND p_content_sha256 !~ '^[0-9a-f]{64}$')
     OR jsonb_typeof(coalesce(p_metadata, '{}'::jsonb)) <> 'object'
     OR octet_length(coalesce(p_metadata, '{}'::jsonb)::text) > 16384 THEN
    RAISE EXCEPTION 'dw_source_attempt_invalid_input';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.dw_sources s WHERE s.id = p_source_id) THEN
    RAISE EXCEPTION 'dw_source_attempt_unknown_source';
  END IF;
  -- The current native onion collector does not yet produce independently
  -- verified Tor control-protocol proofs. Never let this RPC certify them.
  INSERT INTO public.dw_source_attempts (
    source_id, status, route_verified, hs_desc_content_received,
    descriptor_fetched, rendezvous_hop_verified, stream_circuit_bound,
    auth_ok, content_sha256, inspected_items, error_code, metadata
  ) VALUES (
    p_source_id, p_status, false, false, false, false, false,
    false, p_content_sha256, p_inspected_items,
    CASE WHEN p_error_code ~ '^[a-zA-Z0-9_.:-]{1,100}$' THEN p_error_code ELSE NULL END,
    coalesce(p_metadata, '{}'::jsonb)
  )
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$function$;

REVOKE ALL ON FUNCTION public.record_dw_source_attempt(text,text,text,integer,text,jsonb)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_dw_source_attempt(text,text,text,integer,text,jsonb)
  TO service_role;

COMMIT;
