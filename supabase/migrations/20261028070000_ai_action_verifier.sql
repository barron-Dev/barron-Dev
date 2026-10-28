-- AI Action Verifier v1. Additive proposal only; do not apply to production until
-- pgsodium availability, migration history alignment, and isolated DB tests pass.
-- Reuses the existing trust_signing_keys registry and ai_runs identity boundary.

CREATE EXTENSION IF NOT EXISTS pgsodium;

ALTER TABLE public.trust_signing_keys
  DROP CONSTRAINT IF EXISTS trust_signing_keys_domain_check;
ALTER TABLE public.trust_signing_keys
  ADD CONSTRAINT trust_signing_keys_domain_check
  CHECK (
    algorithm = 'ED25519'
    AND purpose = ANY (ARRAY[
      'TRUST_ATTESTATION'::text,
      'TRUST_PROOF'::text,
      'TRUST_CERTIFICATE'::text,
      'TRUST_EVIDENCE'::text,
      'AI_ACTION'::text
    ])
  );
ALTER TABLE public.trust_signing_keys
  DROP CONSTRAINT IF EXISTS trust_signing_keys_purpose_check;
ALTER TABLE public.trust_signing_keys
  ADD CONSTRAINT trust_signing_keys_purpose_check
  CHECK (purpose = ANY (ARRAY[
    'TRUST_PROOF'::text,
    'TRUST_CERTIFICATE'::text,
    'TRUST_EVIDENCE'::text,
    'TRUST_ATTESTATION'::text,
    'AI_ACTION'::text
  ]));

-- Extend the existing tenant signing-key authority; do not create a parallel registry.
CREATE OR REPLACE FUNCTION public.trust_register_signing_key(
  p_tenant_id uuid,
  p_key_id text,
  p_algorithm text,
  p_purpose text,
  p_public_key text,
  p_not_before timestamptz DEFAULT now(),
  p_not_after timestamptz DEFAULT NULL
) RETURNS public.trust_signing_keys
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_catalog'
AS $function$
DECLARE
  outrow public.trust_signing_keys;
BEGIN
  IF coalesce(auth.jwt()->>'role', '') <> 'service_role' THEN
    RAISE EXCEPTION 'service_role_required';
  END IF;
  IF p_tenant_id IS NULL THEN
    RAISE EXCEPTION 'trust_key_tenant_required';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.tenants t WHERE t.id = p_tenant_id) THEN
    RAISE EXCEPTION 'trust_key_tenant_not_found';
  END IF;
  IF p_algorithm <> 'ED25519' THEN
    RAISE EXCEPTION 'unsupported_trust_algorithm';
  END IF;
  IF p_purpose NOT IN (
    'TRUST_ATTESTATION', 'TRUST_PROOF', 'TRUST_CERTIFICATE',
    'TRUST_EVIDENCE', 'AI_ACTION'
  ) THEN
    RAISE EXCEPTION 'invalid_trust_key_purpose';
  END IF;
  IF p_key_id IS NULL OR length(trim(p_key_id)) < 8 OR length(trim(p_key_id)) > 256 THEN
    RAISE EXCEPTION 'invalid_trust_key_id';
  END IF;
  IF p_public_key IS NULL OR p_public_key !~ '^[0-9A-Fa-f]{64}$' THEN
    RAISE EXCEPTION 'invalid_ed25519_public_key';
  END IF;
  IF p_not_after IS NOT NULL AND p_not_after <= coalesce(p_not_before, now()) THEN
    RAISE EXCEPTION 'invalid_trust_key_validity';
  END IF;

  UPDATE public.trust_signing_keys
    SET status = 'RETIRED', retired_at = coalesce(retired_at, now())
    WHERE tenant_id = p_tenant_id AND purpose = p_purpose
      AND status = 'ACTIVE' AND key_id <> trim(p_key_id);

  INSERT INTO public.trust_signing_keys (
    tenant_id, key_id, algorithm, purpose, public_key, status, not_before, not_after
  ) VALUES (
    p_tenant_id, trim(p_key_id), p_algorithm, p_purpose, lower(p_public_key),
    'ACTIVE', coalesce(p_not_before, now()), p_not_after
  ) RETURNING * INTO outrow;
  RETURN outrow;
END
$function$;

CREATE TABLE public.ai_action_verification_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES public.tenants(id),
  run_id uuid NOT NULL REFERENCES public.ai_runs(id),
  event_id uuid NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  actor_id text NOT NULL CHECK (length(btrim(actor_id)) > 0),
  agent_id text,
  action_type text NOT NULL CHECK (length(btrim(action_type)) > 0),
  payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  signer_key_id text NOT NULL CHECK (length(btrim(signer_key_id)) > 0),
  signature_hex text NOT NULL CHECK (signature_hex ~ '^[0-9a-f]{128}$'),
  occurred_at_canonical text NOT NULL CHECK (
    occurred_at_canonical ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$'
  ),
  occurred_at timestamptz NOT NULL,
  verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (tenant_id, run_id, sequence),
  UNIQUE (tenant_id, event_id)
);

CREATE INDEX ai_action_verification_events_run_head_idx
  ON public.ai_action_verification_events (tenant_id, run_id, sequence DESC);

ALTER TABLE public.ai_action_verification_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.ai_action_verification_events FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.ai_action_verification_events TO service_role;

CREATE OR REPLACE FUNCTION public.ai_action_event_hash(
  p_sequence bigint,
  p_event_id uuid,
  p_tenant_id uuid,
  p_run_id uuid,
  p_actor_id text,
  p_agent_id text,
  p_action_type text,
  p_payload_hash text,
  p_previous_hash text,
  p_signer_key_id text,
  p_occurred_at_canonical text
) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path TO 'public', 'pg_catalog', 'extensions'
AS $function$
  SELECT encode(
    extensions.digest(
      convert_to(
        'cyclothone.ai-action.event.v1:' ||
        octet_length(p_sequence::text)::text || ':' || p_sequence::text ||
        octet_length(p_event_id::text)::text || ':' || p_event_id::text ||
        octet_length(p_tenant_id::text)::text || ':' || p_tenant_id::text ||
        octet_length(p_run_id::text)::text || ':' || p_run_id::text ||
        octet_length(p_actor_id)::text || ':' || p_actor_id ||
        octet_length(coalesce(p_agent_id, ''))::text || ':' || coalesce(p_agent_id, '') ||
        octet_length(p_action_type)::text || ':' || p_action_type ||
        octet_length(p_payload_hash)::text || ':' || p_payload_hash ||
        octet_length(p_previous_hash)::text || ':' || p_previous_hash ||
        octet_length(p_signer_key_id)::text || ':' || p_signer_key_id ||
        octet_length(p_occurred_at_canonical)::text || ':' || p_occurred_at_canonical,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )
$function$;

CREATE OR REPLACE FUNCTION public.reject_ai_action_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path TO 'public', 'pg_catalog'
AS $function$
BEGIN
  RAISE EXCEPTION 'ai_action_verification_events_are_append_only';
END
$function$;

CREATE TRIGGER ai_action_events_no_update_or_delete
BEFORE UPDATE OR DELETE ON public.ai_action_verification_events
FOR EACH ROW EXECUTE FUNCTION public.reject_ai_action_event_mutation();

-- Match the Python canonical JSON profile before hashing/signing. Objects are
-- sorted by key; arrays retain ordinal order; strings use PostgreSQL JSON escaping.
CREATE OR REPLACE FUNCTION public.ai_action_canonical_jsonb(p_value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path TO 'pg_catalog'
AS $function$
DECLARE
  v_kind text;
  v_key text;
  v_value jsonb;
  v_item jsonb;
  v_index bigint;
  v_result text;
  v_first boolean;
BEGIN
  v_kind := jsonb_typeof(p_value);
  IF v_kind = 'object' THEN
    v_result := '{';
    v_first := true;
    FOR v_key, v_value IN
      SELECT key, value FROM jsonb_each(p_value) ORDER BY key COLLATE "C"
    LOOP
      IF NOT v_first THEN v_result := v_result || ','; END IF;
      v_result := v_result || to_json(v_key)::text || ':' ||
        public.ai_action_canonical_jsonb(v_value);
      v_first := false;
    END LOOP;
    RETURN v_result || '}';
  ELSIF v_kind = 'array' THEN
    v_result := '[';
    v_first := true;
    FOR v_item, v_index IN
      SELECT value, ordinality FROM jsonb_array_elements(p_value) WITH ORDINALITY
    LOOP
      IF NOT v_first THEN v_result := v_result || ','; END IF;
      v_result := v_result || public.ai_action_canonical_jsonb(v_item);
      v_first := false;
    END LOOP;
    RETURN v_result || ']';
  ELSIF v_kind = 'string' THEN
    RETURN to_json(p_value #>> '{}')::text;
  ELSIF v_kind = 'number' THEN
    -- Shared profile permits safe integers only. Reject fractional values and
    -- integers JavaScript cannot represent exactly.
    IF (p_value #>> '{}') !~ '^-?(0|[1-9][0-9]*)$'
       OR abs((p_value #>> '{}')::numeric) > 9007199254740991 THEN
      RAISE EXCEPTION 'ai_action_number_outside_canonical_profile';
    END IF;
    RETURN p_value::text;
  ELSE
    RETURN p_value::text;
  END IF;
END
$function$;

CREATE OR REPLACE FUNCTION public.commit_ai_action_verification_event(
  p_tenant_id uuid,
  p_run_id uuid,
  p_event_id uuid,
  p_sequence bigint,
  p_actor_id text,
  p_agent_id text,
  p_action_type text,
  p_payload_canonical text,
  p_payload_hash text,
  p_previous_hash text,
  p_event_hash text,
  p_signer_key_id text,
  p_signature_hex text,
  p_occurred_at_canonical text
) RETURNS public.ai_action_verification_events
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'pg_catalog', 'extensions', 'pgsodium'
AS $function$
DECLARE
  v_run_tenant uuid;
  v_run_agent uuid;
  v_previous_hash text;
  v_payload jsonb;
  v_payload_hash text;
  v_event_hash text;
  v_key public.trust_signing_keys%rowtype;
  v_event public.ai_action_verification_events%rowtype;
  v_occurred_at timestamptz;
BEGIN
  IF p_tenant_id IS NULL OR p_run_id IS NULL OR p_event_id IS NULL
     OR p_sequence IS NULL OR p_sequence < 1
     OR p_actor_id IS NULL OR length(btrim(p_actor_id)) = 0
     OR p_action_type IS NULL OR length(btrim(p_action_type)) = 0
     OR p_signer_key_id IS NULL OR length(btrim(p_signer_key_id)) = 0 THEN
    RAISE EXCEPTION 'invalid_ai_action_receipt';
  END IF;
  IF p_payload_canonical IS NULL OR length(p_payload_canonical) > 1048576 THEN
    RAISE EXCEPTION 'invalid_ai_action_payload_size';
  END IF;
  IF p_payload_hash IS NULL OR p_payload_hash !~ '^[0-9a-f]{64}$'
     OR p_previous_hash IS NULL OR p_previous_hash !~ '^[0-9a-f]{64}$'
     OR p_event_hash IS NULL OR p_event_hash !~ '^[0-9a-f]{64}$'
     OR p_signature_hex IS NULL OR p_signature_hex !~ '^[0-9a-f]{128}$' THEN
    RAISE EXCEPTION 'invalid_ai_action_hash_or_signature_format';
  END IF;
  IF p_occurred_at_canonical IS NULL OR p_occurred_at_canonical !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$' THEN
    RAISE EXCEPTION 'invalid_ai_action_timestamp_format';
  END IF;

  -- Hash the exact canonical UTF-8 bytes signed by the backend. The raw payload
  -- is deliberately not persisted in this ledger.
  v_payload := p_payload_canonical::jsonb;
  IF jsonb_typeof(v_payload) <> 'object' THEN
    RAISE EXCEPTION 'ai_action_payload_must_be_json_object';
  END IF;
  IF public.ai_action_canonical_jsonb(v_payload) IS DISTINCT FROM p_payload_canonical THEN
    RAISE EXCEPTION 'ai_action_payload_not_canonical';
  END IF;
  v_payload_hash := encode(
    extensions.digest(convert_to(p_payload_canonical, 'UTF8'), 'sha256'), 'hex'
  );
  IF v_payload_hash <> p_payload_hash THEN
    RAISE EXCEPTION 'ai_action_payload_hash_mismatch';
  END IF;
  v_occurred_at := p_occurred_at_canonical::timestamptz;

  -- Serialize commits per run and bind the receipt to the existing AI run.
  SELECT tenant_id, agent_id INTO v_run_tenant, v_run_agent
    FROM public.ai_runs WHERE id = p_run_id FOR UPDATE;
  IF NOT FOUND OR v_run_tenant IS DISTINCT FROM p_tenant_id THEN
    RAISE EXCEPTION 'ai_action_run_tenant_mismatch';
  END IF;
  IF p_agent_id IS DISTINCT FROM v_run_agent::text THEN
    RAISE EXCEPTION 'ai_action_agent_binding_mismatch';
  END IF;

  IF p_sequence = 1 THEN
    IF p_previous_hash <> repeat('0', 64) THEN
      RAISE EXCEPTION 'ai_action_genesis_hash_mismatch';
    END IF;
  ELSE
    SELECT event_hash INTO v_previous_hash
      FROM public.ai_action_verification_events
      WHERE tenant_id = p_tenant_id AND run_id = p_run_id
        AND sequence = p_sequence - 1
      FOR SHARE;
    IF NOT FOUND OR v_previous_hash IS DISTINCT FROM p_previous_hash THEN
      RAISE EXCEPTION 'ai_action_previous_hash_mismatch';
    END IF;
  END IF;

  v_event_hash := public.ai_action_event_hash(
    p_sequence, p_event_id, p_tenant_id, p_run_id, p_actor_id, p_agent_id,
    p_action_type, v_payload_hash, p_previous_hash, p_signer_key_id,
    p_occurred_at_canonical
  );
  IF v_event_hash <> p_event_hash THEN
    RAISE EXCEPTION 'ai_action_event_hash_mismatch';
  END IF;

  SELECT * INTO v_key
    FROM public.trust_signing_keys
    WHERE tenant_id = p_tenant_id AND key_id = p_signer_key_id
      AND purpose = 'AI_ACTION' AND algorithm = 'ED25519' AND status = 'ACTIVE'
      AND (not_before IS NULL OR not_before <= clock_timestamp())
      AND (not_after IS NULL OR not_after > clock_timestamp())
    FOR SHARE;
  IF NOT FOUND OR v_key.public_key !~ '^[0-9a-fA-F]{64}$' THEN
    RAISE EXCEPTION 'ai_action_signing_key_not_active';
  END IF;

  -- Actual database-side Ed25519 verification; no API-supplied boolean is trusted.
  IF NOT pgsodium.crypto_sign_verify_detached(
    decode(p_signature_hex, 'hex'),
    convert_to(v_event_hash, 'UTF8'),
    decode(v_key.public_key, 'hex')
  ) THEN
    RAISE EXCEPTION 'ai_action_signature_invalid';
  END IF;

  INSERT INTO public.ai_action_verification_events (
    tenant_id, run_id, event_id, sequence, actor_id, agent_id, action_type,
    payload_hash, previous_hash, event_hash, signer_key_id, signature_hex,
    occurred_at_canonical, occurred_at
  ) VALUES (
    p_tenant_id, p_run_id, p_event_id, p_sequence, p_actor_id, p_agent_id,
    p_action_type, v_payload_hash, p_previous_hash, v_event_hash, p_signer_key_id,
    lower(p_signature_hex), p_occurred_at_canonical, v_occurred_at
  ) RETURNING * INTO v_event;

  RETURN v_event;
END
$function$;

REVOKE ALL ON FUNCTION public.ai_action_event_hash(bigint,uuid,uuid,uuid,text,text,text,text,text,text,text)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.reject_ai_action_event_mutation()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.commit_ai_action_verification_event(uuid,uuid,uuid,bigint,text,text,text,text,text,text,text,text,text,text)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.commit_ai_action_verification_event(uuid,uuid,uuid,bigint,text,text,text,text,text,text,text,text,text,text)
  TO service_role;

