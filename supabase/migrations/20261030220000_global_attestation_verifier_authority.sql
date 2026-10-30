-- Trust roots for independently operated platform-attestation verifiers.
CREATE TABLE IF NOT EXISTS public.global_attestation_verifier_keys (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 verifier_name text NOT NULL CHECK (length(verifier_name) BETWEEN 3 AND 120),
 platform text NOT NULL CHECK (platform IN ('android','ios','windows','macos','linux','server')),
 public_key_pem text NOT NULL CHECK (length(public_key_pem) BETWEEN 80 AND 4096),
 key_fingerprint_sha256 text NOT NULL UNIQUE CHECK (key_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
 policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 80),
 status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED')),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK (not_after > not_before)
);
CREATE TABLE IF NOT EXISTS public.global_attestation_verifier_decisions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 principal_id uuid NOT NULL,
 device_id uuid NOT NULL,
 verifier_key_id uuid NOT NULL REFERENCES public.global_attestation_verifier_keys(id),
 platform text NOT NULL,
 attestation_format text NOT NULL,
 assurance_level text NOT NULL CHECK (assurance_level IN ('hardware_attested','workload_attested')),
 evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
 assertion_sha256 text NOT NULL CHECK (assertion_sha256 ~ '^[a-f0-9]{64}$'),
 challenge_id uuid NOT NULL,
 valid_until timestamptz NOT NULL,
 policy_version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES public.global_principals(tenant_id,id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES public.global_device_attestations(tenant_id,id),
 FOREIGN KEY(challenge_id,tenant_id,principal_id) REFERENCES public.global_device_challenges(id,tenant_id,principal_id)
);
ALTER TABLE public.global_attestation_verifier_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_attestation_verifier_decisions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.global_attestation_verifier_keys,public.global_attestation_verifier_decisions FROM PUBLIC,anon,authenticated;
GRANT SELECT ON public.global_attestation_verifier_keys TO service_role;
GRANT SELECT,INSERT ON public.global_attestation_verifier_decisions TO service_role;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON public.global_attestation_verifier_decisions FROM PUBLIC,anon,authenticated,service_role;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON public.global_attestation_verifier_keys FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.global_promote_attested_device_atomic(
 p_tenant_id uuid,p_principal_id uuid,p_device_id uuid,p_challenge_id uuid,
 p_device_fingerprint text,p_context_sha256 text,p_nonce text,
 p_verifier_key_id uuid,p_platform text,p_attestation_format text,
 p_assurance_level text,p_evidence_sha256 text,p_assertion_sha256 text,
 p_valid_until timestamptz,p_policy_version text
) RETURNS TABLE(decision text,reason_code text,decision_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
 v_now timestamptz:=clock_timestamp();
 v_device public.global_device_attestations%ROWTYPE;
 v_key public.global_attestation_verifier_keys%ROWTYPE;
 v_principal_state text;
 v_decision uuid;
 v_consumed boolean:=false;
 v_reason text;
BEGIN
 SELECT lifecycle_state INTO v_principal_state FROM public.global_principals
 WHERE id=p_principal_id AND tenant_id=p_tenant_id;
 SELECT d.* INTO v_device FROM public.global_device_attestations d
 JOIN public.devices pd ON pd.id=d.platform_device_id AND pd.tenant_id=d.tenant_id
 WHERE d.id=p_device_id AND d.tenant_id=p_tenant_id AND d.principal_id=p_principal_id
 AND d.device_fingerprint=p_device_fingerprint AND pd.status='active'
 FOR UPDATE OF d;
 SELECT * INTO v_key FROM public.global_attestation_verifier_keys
 WHERE id=p_verifier_key_id AND status='ACTIVE' AND platform=p_platform
 AND policy_version=p_policy_version AND not_before<=v_now AND not_after>v_now;
 IF v_device.id IS NOT NULL AND v_key.id IS NOT NULL THEN
  UPDATE public.global_device_challenges SET consumed_at=v_now
  WHERE id=p_challenge_id AND tenant_id=p_tenant_id AND principal_id=p_principal_id
  AND device_fingerprint=p_device_fingerprint AND purpose='device_attestation'
  AND context_sha256=p_context_sha256 AND nonce=p_nonce
  AND consumed_at IS NULL AND expires_at>v_now;
  v_consumed:=FOUND;
 END IF;
 IF v_principal_state IS DISTINCT FROM 'ACTIVE' THEN v_reason:='global_principal_not_active';
 ELSIF v_device.id IS NULL THEN v_reason:='device_not_active_or_registered';
 ELSIF v_key.id IS NULL THEN v_reason:='attestation_verifier_not_trusted';
 ELSIF NOT v_consumed THEN v_reason:='attestation_challenge_invalid_or_replayed';
 ELSIF p_valid_until<=v_now OR p_valid_until>v_now+interval '24 hours' THEN v_reason:='attestation_validity_out_of_policy';
 ELSIF p_evidence_sha256 !~ '^[a-f0-9]{64}$' OR p_assertion_sha256 !~ '^[a-f0-9]{64}$' THEN v_reason:='attestation_evidence_invalid';
 ELSIF p_platform<>v_device.platform OR (v_device.attestation_format<>'proof_of_possession' AND p_attestation_format<>v_device.attestation_format) THEN v_reason:='attestation_platform_mismatch';
 ELSIF p_assurance_level NOT IN ('hardware_attested','workload_attested') THEN v_reason:='attestation_assurance_invalid';
 ELSIF v_device.revoked_at IS NOT NULL OR v_device.attestation_state='REVOKED' THEN v_reason:='device_revoked_requires_new_enrollment';
 ELSE v_reason:='verified'; END IF;
 IF v_reason='verified' THEN
  UPDATE public.global_device_attestations SET attestation_state='VERIFIED',
   attestation_format=p_attestation_format,assurance_level=p_assurance_level,attestation_evidence_sha256=p_evidence_sha256,
   last_attested_at=v_now,valid_until=p_valid_until
  WHERE id=p_device_id AND tenant_id=p_tenant_id;
  INSERT INTO public.global_attestation_verifier_decisions(
   tenant_id,principal_id,device_id,verifier_key_id,platform,attestation_format,
   assurance_level,evidence_sha256,assertion_sha256,challenge_id,valid_until,policy_version
  ) VALUES(p_tenant_id,p_principal_id,p_device_id,p_verifier_key_id,p_platform,p_attestation_format,
   p_assurance_level,p_evidence_sha256,p_assertion_sha256,p_challenge_id,p_valid_until,p_policy_version)
  RETURNING id INTO v_decision;
 END IF;
 RETURN QUERY SELECT CASE WHEN v_reason='verified' THEN 'VERIFIED' ELSE 'BLOCKED' END,v_reason,v_decision;
END $$;
REVOKE ALL ON FUNCTION public.global_promote_attested_device_atomic(uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,text,text,text,timestamptz,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_promote_attested_device_atomic(uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,text,text,text,timestamptz,text) TO service_role;
COMMENT ON TABLE public.global_attestation_verifier_keys IS 'Pinned verifier signing keys. No keys are trusted by default; provisioning requires controlled operator procedure.';
COMMENT ON TABLE public.global_attestation_verifier_decisions IS 'Immutable evidence of trusted verifier decisions; records assertion and evidence digests.';
