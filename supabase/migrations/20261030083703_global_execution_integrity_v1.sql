-- Cyclothone Global Supply Chain & Execution Integrity v1
-- Proof of possession is not hardware attestation. New devices are UNVERIFIED until a trusted
-- platform-specific verifier promotes them through a separately controlled path.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;
CREATE TABLE IF NOT EXISTS public.global_principals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
 principal_kind text NOT NULL CHECK (principal_kind IN ('external_client','developer','employee','vendor','system')),
 subject_fingerprint text NOT NULL CHECK (subject_fingerprint ~ '^[a-f0-9]{64}$'),
 lifecycle_state text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_state IN ('ACTIVE','SUSPENDED','REVOKED')),
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,principal_kind,subject_fingerprint), UNIQUE(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS global_principals_tenant_kind_idx ON public.global_principals(tenant_id,principal_kind);
CREATE TABLE IF NOT EXISTS public.global_device_attestations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 device_fingerprint text NOT NULL CHECK (device_fingerprint ~ '^[a-f0-9]{64}$'), hardware_public_key text NOT NULL,
 key_algorithm text NOT NULL CHECK (key_algorithm='ed25519'),
 platform text NOT NULL CHECK (platform IN ('android','ios','windows','macos','linux','server')),
 attestation_format text NOT NULL CHECK (attestation_format IN ('proof_of_possession','webauthn','android_key','play_integrity','apple_app_attest','tpm2','workload')),
 attestation_state text NOT NULL DEFAULT 'UNVERIFIED' CHECK (attestation_state IN ('VERIFIED','COMPROMISED','UNVERIFIED','REVOKED','EXPIRED')),
 assurance_level text NOT NULL DEFAULT 'key_possession' CHECK (assurance_level IN ('none','key_possession','hardware_backed','hardware_attested','workload_attested')),
 attestation_evidence_sha256 text CHECK (attestation_evidence_sha256 IS NULL OR attestation_evidence_sha256 ~ '^[a-f0-9]{64}$'),
 last_attested_at timestamptz, valid_until timestamptz, created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
 FOREIGN KEY(tenant_id,principal_id) REFERENCES public.global_principals(tenant_id,id) ON DELETE CASCADE,
 UNIQUE(tenant_id,principal_id,device_fingerprint), UNIQUE(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS global_device_attestations_gate_idx ON public.global_device_attestations(tenant_id,principal_id,attestation_state,last_attested_at DESC);
CREATE TABLE IF NOT EXISTS public.global_device_challenges (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 device_fingerprint text NOT NULL CHECK (device_fingerprint ~ '^[a-f0-9]{64}$'),
 purpose text NOT NULL CHECK (purpose IN ('device_attestation','sensitive_action','sbom_submission')),
 context_sha256 text NOT NULL CHECK (context_sha256 ~ '^[a-f0-9]{64}$'), nonce text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, consumed_at timestamptz,
 FOREIGN KEY(tenant_id,principal_id) REFERENCES public.global_principals(tenant_id,id) ON DELETE CASCADE,
 UNIQUE(id,tenant_id,principal_id)
);
CREATE INDEX IF NOT EXISTS global_device_challenges_expiry_idx ON public.global_device_challenges(expires_at) WHERE consumed_at IS NULL;
CREATE TABLE IF NOT EXISTS public.global_execution_receipts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, principal_id uuid NOT NULL, device_id uuid, challenge_id uuid,
 action_type text NOT NULL, action_payload_sha256 text NOT NULL CHECK (action_payload_sha256 ~ '^[a-f0-9]{64}$'),
 signature_sha256 text, decision text NOT NULL CHECK (decision IN ('AUTHORIZED','BLOCKED')), reason_code text NOT NULL,
 policy_version text NOT NULL DEFAULT 'global-execution-gate-1', created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES public.global_principals(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id) REFERENCES public.global_device_attestations(tenant_id,id),
 FOREIGN KEY(challenge_id,tenant_id,principal_id) REFERENCES public.global_device_challenges(id,tenant_id,principal_id)
);
CREATE INDEX IF NOT EXISTS global_execution_receipts_tenant_time_idx ON public.global_execution_receipts(tenant_id,created_at DESC);
CREATE TABLE IF NOT EXISTS public.global_package_intel (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ecosystem text NOT NULL, purl text NOT NULL, version text NOT NULL,
 package_sha256 text CHECK (package_sha256 IS NULL OR package_sha256 ~ '^[a-f0-9]{64}$'),
 status text NOT NULL CHECK (status IN ('malicious','compromised','suspicious','unknown')),
 source_id text NOT NULL, source_record_ref text, evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL, valid_until timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(ecosystem,purl,version,source_id,evidence_sha256)
);
CREATE INDEX IF NOT EXISTS global_package_intel_lookup_idx ON public.global_package_intel(purl,version,status);
CREATE TABLE IF NOT EXISTS public.global_sbom_artifacts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, principal_id uuid NOT NULL, device_id uuid,
 project_ref text NOT NULL CHECK(length(project_ref) BETWEEN 1 AND 240), format text NOT NULL CHECK(format='CycloneDX'),
 spec_version text NOT NULL, sbom_sha256 text NOT NULL CHECK(sbom_sha256 ~ '^[a-f0-9]{64}$'),
 signature_sha256 text NOT NULL CHECK(signature_sha256 ~ '^[a-f0-9]{64}$'),
 component_count integer NOT NULL CHECK(component_count BETWEEN 0 AND 50000),
 gate_decision text NOT NULL CHECK(gate_decision IN ('BLOCKED','REVIEW_REQUIRED')),
 scan_summary jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(scan_summary)='object'), created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES public.global_principals(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,device_id) REFERENCES public.global_device_attestations(tenant_id,id), UNIQUE(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS global_sbom_artifacts_tenant_time_idx ON public.global_sbom_artifacts(tenant_id,created_at DESC);
CREATE TABLE IF NOT EXISTS public.global_sbom_components (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, artifact_id uuid NOT NULL,
 purl text NOT NULL, ecosystem text NOT NULL, name text NOT NULL, version text NOT NULL,
 package_sha256 text CHECK(package_sha256 IS NULL OR package_sha256 ~ '^[a-f0-9]{64}$'),
 intel_status text NOT NULL CHECK(intel_status IN ('malicious','compromised','suspicious','unknown')), intel_evidence_sha256 text,
 FOREIGN KEY(tenant_id,artifact_id) REFERENCES public.global_sbom_artifacts(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS global_sbom_components_lookup_idx ON public.global_sbom_components(purl,version);
CREATE INDEX IF NOT EXISTS global_sbom_components_tenant_artifact_idx ON public.global_sbom_components(tenant_id,artifact_id);
ALTER TABLE public.global_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_device_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_device_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_execution_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_package_intel ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_sbom_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.global_sbom_components ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.global_principals,public.global_device_attestations,public.global_device_challenges,public.global_execution_receipts,public.global_package_intel,public.global_sbom_artifacts,public.global_sbom_components FROM anon,authenticated;
GRANT SELECT ON public.global_principals,public.global_device_attestations,public.global_device_challenges,public.global_execution_receipts,public.global_package_intel,public.global_sbom_artifacts,public.global_sbom_components TO service_role;
GRANT INSERT ON public.global_execution_receipts,public.global_sbom_artifacts,public.global_sbom_components TO service_role;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON public.global_execution_receipts,public.global_sbom_artifacts,public.global_sbom_components FROM anon,authenticated,service_role;
CREATE OR REPLACE FUNCTION public.global_resolve_principal(p_tenant_id uuid,p_principal_kind text,p_subject_fingerprint text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_id uuid;
BEGIN
 IF p_principal_kind NOT IN ('external_client','developer','employee','vendor','system') OR p_subject_fingerprint !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'invalid_global_principal'; END IF;
 INSERT INTO public.global_principals(tenant_id,principal_kind,subject_fingerprint) VALUES(p_tenant_id,p_principal_kind,p_subject_fingerprint)
 ON CONFLICT(tenant_id,principal_kind,subject_fingerprint) DO UPDATE SET lifecycle_state=public.global_principals.lifecycle_state RETURNING id INTO v_id;
 RETURN v_id;
END; $$;
CREATE OR REPLACE FUNCTION public.global_issue_device_challenge(p_tenant_id uuid,p_principal_id uuid,p_device_fingerprint text,p_purpose text,p_context_sha256 text)
RETURNS TABLE(challenge_id uuid,challenge_nonce text,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,extensions AS $$
DECLARE v_id uuid; v_nonce text; v_expiry timestamptz;
BEGIN
 IF p_device_fingerprint !~ '^[a-f0-9]{64}$' OR p_context_sha256 !~ '^[a-f0-9]{64}$' OR p_purpose NOT IN ('device_attestation','sensitive_action','sbom_submission') THEN RAISE EXCEPTION 'invalid_global_device_challenge'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.global_principals gp WHERE gp.id=p_principal_id AND gp.tenant_id=p_tenant_id AND gp.lifecycle_state='ACTIVE') THEN RAISE EXCEPTION 'global_principal_not_active'; END IF;
 v_nonce:=encode(extensions.gen_random_bytes(32),'hex'); v_expiry:=now()+interval '3 minutes';
 INSERT INTO public.global_device_challenges(tenant_id,principal_id,device_fingerprint,purpose,context_sha256,nonce,expires_at)
 VALUES(p_tenant_id,p_principal_id,p_device_fingerprint,p_purpose,p_context_sha256,v_nonce,v_expiry) RETURNING id INTO v_id;
 RETURN QUERY SELECT v_id,v_nonce,v_expiry;
END; $$;
CREATE OR REPLACE FUNCTION public.global_consume_device_challenge(p_challenge_id uuid,p_tenant_id uuid,p_principal_id uuid,p_device_fingerprint text,p_purpose text,p_context_sha256 text,p_nonce text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_id uuid;
BEGIN
 UPDATE public.global_device_challenges SET consumed_at=now()
 WHERE id=p_challenge_id AND tenant_id=p_tenant_id AND principal_id=p_principal_id AND device_fingerprint=p_device_fingerprint
 AND purpose=p_purpose AND context_sha256=p_context_sha256 AND nonce=p_nonce AND consumed_at IS NULL AND expires_at>now()
 RETURNING id INTO v_id;
 RETURN v_id IS NOT NULL;
END; $$;
CREATE OR REPLACE FUNCTION public.global_register_device_key(p_tenant_id uuid,p_principal_id uuid,p_device_fingerprint text,p_public_key text,p_platform text,p_attestation_format text,p_attestation_evidence_sha256 text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_id uuid;
BEGIN
 IF p_attestation_format NOT IN ('proof_of_possession','webauthn','android_key','play_integrity','apple_app_attest','tpm2','workload') THEN RAISE EXCEPTION 'unsupported_attestation_format'; END IF;
 IF p_platform NOT IN ('android','ios','windows','macos','linux','server') THEN RAISE EXCEPTION 'unsupported_platform'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.global_principals gp WHERE gp.id=p_principal_id AND gp.tenant_id=p_tenant_id AND gp.lifecycle_state='ACTIVE') THEN RAISE EXCEPTION 'global_principal_not_active'; END IF;
 INSERT INTO public.global_device_attestations(tenant_id,principal_id,device_fingerprint,hardware_public_key,key_algorithm,platform,attestation_format,attestation_state,assurance_level,attestation_evidence_sha256,last_attested_at)
 VALUES(p_tenant_id,p_principal_id,p_device_fingerprint,p_public_key,'ed25519',p_platform,p_attestation_format,'UNVERIFIED','key_possession',p_attestation_evidence_sha256,now())
 ON CONFLICT(tenant_id,principal_id,device_fingerprint) DO UPDATE SET hardware_public_key=excluded.hardware_public_key,platform=excluded.platform,
 attestation_format=excluded.attestation_format,attestation_state='UNVERIFIED',assurance_level='key_possession',
 attestation_evidence_sha256=excluded.attestation_evidence_sha256,last_attested_at=now(),valid_until=NULL,revoked_at=NULL RETURNING id INTO v_id;
 RETURN v_id;
END; $$;
REVOKE ALL ON FUNCTION public.global_resolve_principal(uuid,text,text) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.global_issue_device_challenge(uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.global_consume_device_challenge(uuid,uuid,uuid,text,text,text,text) FROM PUBLIC,anon,authenticated;
REVOKE ALL ON FUNCTION public.global_register_device_key(uuid,uuid,text,text,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_resolve_principal(uuid,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.global_issue_device_challenge(uuid,uuid,text,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.global_consume_device_challenge(uuid,uuid,uuid,text,text,text,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.global_register_device_key(uuid,uuid,text,text,text,text,text) TO service_role;
COMMENT ON TABLE public.global_device_attestations IS 'Universal device key registry. Registration only creates UNVERIFIED state; trusted platform verifier required for VERIFIED.';
COMMENT ON TABLE public.global_package_intel IS 'Source-backed package intelligence. Missing indicators are unknown, never clean.';
