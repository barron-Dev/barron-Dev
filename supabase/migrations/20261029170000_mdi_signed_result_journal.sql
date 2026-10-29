-- Source-only until live migration history is reconciled. No production apply in this PR.
CREATE TABLE IF NOT EXISTS public.mdi_journal_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contract_id text NOT NULL UNIQUE CHECK (length(contract_id) BETWEEN 1 AND 128),
  tenant_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type ~ '^[A-Z][A-Z0-9_]{1,79}$'),
  disposition text NOT NULL CHECK (disposition IN ('threat_detected','verified_clean','partial_coverage','unknown','source_unavailable','human_review_required')),
  evidence_hash text NOT NULL CHECK (evidence_hash ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
  previous_hash text NOT NULL CHECK (previous_hash ~ '^[a-f0-9]{64}$'),
  current_hash text NOT NULL UNIQUE CHECK (current_hash ~ '^[a-f0-9]{64}$'),
  signer_key_id text NOT NULL,
  signature_b64 text NOT NULL,
  created_at timestamptz NOT NULL,
  persisted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, previous_hash)
);
CREATE INDEX IF NOT EXISTS mdi_journal_events_tenant_created_idx
  ON public.mdi_journal_events (tenant_id, created_at DESC);
ALTER TABLE public.mdi_journal_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.mdi_journal_events FROM anon, authenticated;
GRANT SELECT ON public.mdi_journal_events TO service_role;
GRANT INSERT ON public.mdi_journal_events TO service_role;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.mdi_journal_events FROM anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.mdi_journal_reject_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'MDI journal is append-only; % is forbidden', TG_OP
    USING ERRCODE = '55000';
END $$;
REVOKE ALL ON FUNCTION public.mdi_journal_reject_mutation() FROM PUBLIC, anon, authenticated, service_role;
CREATE TRIGGER mdi_journal_no_update_delete
  BEFORE UPDATE OR DELETE ON public.mdi_journal_events
  FOR EACH ROW EXECUTE FUNCTION public.mdi_journal_reject_mutation();

CREATE OR REPLACE FUNCTION public.mdi_append_journal_event(
  p_contract_id text, p_tenant_id uuid, p_event_type text, p_disposition text,
  p_evidence_hash text, p_payload jsonb, p_previous_hash text, p_current_hash text,
  p_signer_key_id text, p_signature_b64 text, p_created_at timestamptz
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, auth AS $$
DECLARE v_previous text; v_id uuid;
BEGIN
  IF coalesce(auth.role(), '') <> 'service_role' THEN
    RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
  END IF;
  IF p_tenant_id IS NULL OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR p_evidence_hash !~ '^[a-f0-9]{64}$'
     OR p_current_hash !~ '^[a-f0-9]{64}$'
     OR p_previous_hash !~ '^[a-f0-9]{64}$'
     OR length(coalesce(p_signature_b64,'')) < 40
     OR length(coalesce(p_signer_key_id,'')) NOT BETWEEN 1 AND 128 THEN
    RAISE EXCEPTION 'invalid MDI contract fields' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 77192));
  SELECT current_hash INTO v_previous FROM public.mdi_journal_events
    WHERE tenant_id = p_tenant_id ORDER BY persisted_at DESC, id DESC LIMIT 1;
  IF p_previous_hash <> coalesce(v_previous, repeat('0',64)) THEN
    RAISE EXCEPTION 'journal head mismatch' USING ERRCODE = '40001';
  END IF;
  INSERT INTO public.mdi_journal_events
    (contract_id,tenant_id,event_type,disposition,evidence_hash,payload,previous_hash,current_hash,signer_key_id,signature_b64,created_at)
  VALUES
    (p_contract_id,p_tenant_id,p_event_type,p_disposition,p_evidence_hash,p_payload,p_previous_hash,p_current_hash,p_signer_key_id,p_signature_b64,p_created_at)
  RETURNING id INTO v_id;
  RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION public.mdi_append_journal_event(text,uuid,text,text,text,jsonb,text,text,text,text,timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mdi_append_journal_event(text,uuid,text,text,text,jsonb,text,text,text,text,timestamptz) TO service_role;
