-- Bind global cryptographic attestations to Cyclothone's existing tenant device registry.
CREATE UNIQUE INDEX IF NOT EXISTS devices_tenant_id_id_global_integrity_uidx
  ON public.devices(tenant_id,id);

ALTER TABLE public.global_device_attestations
  ADD COLUMN IF NOT EXISTS platform_device_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='global_device_attestations_platform_device_fk'
      AND conrelid='public.global_device_attestations'::regclass
  ) THEN
    ALTER TABLE public.global_device_attestations
      ADD CONSTRAINT global_device_attestations_platform_device_fk
      FOREIGN KEY(tenant_id,platform_device_id)
      REFERENCES public.devices(tenant_id,id)
      ON DELETE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS global_device_attestations_platform_device_idx
  ON public.global_device_attestations(tenant_id,platform_device_id)
  WHERE platform_device_id IS NOT NULL;

-- Remove the earlier unbound registration signature so service_role cannot bypass the
-- canonical device registry by continuing to call the old RPC.
DROP FUNCTION IF EXISTS public.global_register_device_key(uuid,uuid,text,text,text,text,text);

CREATE OR REPLACE FUNCTION public.global_register_device_key(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_platform_device_id uuid,
  p_device_fingerprint text,
  p_public_key text,
  p_platform text,
  p_attestation_format text,
  p_attestation_evidence_sha256 text
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF p_device_fingerprint IS NULL OR p_device_fingerprint !~ '^[a-f0-9]{64}$'
     OR p_public_key IS NULL OR length(p_public_key) < 80 OR length(p_public_key) > 4096
     OR p_attestation_format NOT IN ('proof_of_possession','webauthn','android_key','play_integrity','apple_app_attest','tpm2','workload')
     OR p_platform NOT IN ('android','ios','windows','macos','linux','server')
     OR (p_attestation_evidence_sha256 IS NOT NULL AND p_attestation_evidence_sha256 !~ '^[a-f0-9]{64}$') THEN
    RAISE EXCEPTION 'invalid_global_device_registration';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_principals gp
    WHERE gp.id=p_principal_id AND gp.tenant_id=p_tenant_id AND gp.lifecycle_state='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'global_principal_not_active';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.devices d
    WHERE d.id=p_platform_device_id AND d.tenant_id=p_tenant_id AND d.status='active'
  ) THEN
    RAISE EXCEPTION 'platform_device_not_active_or_not_found';
  END IF;

  INSERT INTO public.global_device_attestations(
    tenant_id,principal_id,platform_device_id,device_fingerprint,hardware_public_key,key_algorithm,
    platform,attestation_format,attestation_state,assurance_level,attestation_evidence_sha256,last_attested_at
  ) VALUES (
    p_tenant_id,p_principal_id,p_platform_device_id,p_device_fingerprint,p_public_key,'ed25519',
    p_platform,p_attestation_format,'UNVERIFIED','key_possession',p_attestation_evidence_sha256,now()
  )
  ON CONFLICT(tenant_id,principal_id,device_fingerprint) DO UPDATE SET
    platform_device_id=excluded.platform_device_id,
    hardware_public_key=excluded.hardware_public_key,
    platform=excluded.platform,
    attestation_format=excluded.attestation_format,
    attestation_state='UNVERIFIED',
    assurance_level='key_possession',
    attestation_evidence_sha256=excluded.attestation_evidence_sha256,
    last_attested_at=now(),
    valid_until=NULL,
    revoked_at=NULL
  RETURNING id INTO v_id;

  RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION public.global_register_device_key(uuid,uuid,uuid,text,text,text,text,text)
  FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_register_device_key(uuid,uuid,uuid,text,text,text,text,text)
  TO service_role;
