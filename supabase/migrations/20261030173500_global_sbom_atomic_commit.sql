-- Atomic SBOM evidence + execution receipt persistence.
-- This RPC independently rechecks principal/device freshness and commits all evidence in one transaction.
CREATE OR REPLACE FUNCTION public.global_commit_sbom_scan(
  p_tenant_id uuid,
  p_principal_id uuid,
  p_device_id uuid,
  p_project_ref text,
  p_spec_version text,
  p_sbom_sha256 text,
  p_signature_sha256 text,
  p_component_count integer,
  p_gate_decision text,
  p_scan_summary jsonb,
  p_components jsonb
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
  v_artifact_id uuid;
  v_now timestamptz := now();
BEGIN
  IF p_project_ref IS NULL OR length(p_project_ref) NOT BETWEEN 1 AND 240
     OR p_spec_version IS NULL OR length(p_spec_version) NOT BETWEEN 1 AND 32
     OR p_sbom_sha256 IS NULL OR p_sbom_sha256 !~ '^[a-f0-9]{64}
    RAISE EXCEPTION 'invalid_sbom_commit_payload';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_principals gp
    WHERE gp.id=p_principal_id AND gp.tenant_id=p_tenant_id AND gp.lifecycle_state='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'global_principal_not_active';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_device_attestations d
    WHERE d.id=p_device_id AND d.tenant_id=p_tenant_id AND d.principal_id=p_principal_id
      AND d.attestation_state='VERIFIED'
      AND d.last_attested_at >= v_now - interval '5 minutes'
      AND (d.valid_until IS NULL OR d.valid_until > v_now)
      AND d.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'verified_hardware_attestation_required';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_to_recordset(p_components) AS c(
      purl text, ecosystem text, name text, version text, package_sha256 text,
      intel_status text, intel_evidence_sha256 text
    )
    WHERE c.purl IS NULL OR c.ecosystem IS NULL OR c.name IS NULL OR c.version IS NULL
       OR c.intel_status IS NULL
       OR c.intel_status NOT IN ('malicious','compromised','suspicious','unknown')
       OR (c.package_sha256 IS NOT NULL AND c.package_sha256 !~ '^[a-f0-9]{64}$')
       OR (c.intel_evidence_sha256 IS NOT NULL AND c.intel_evidence_sha256 !~ '^[a-f0-9]{64}$')
  ) THEN
    RAISE EXCEPTION 'invalid_sbom_component_payload';
  END IF;

  INSERT INTO public.global_sbom_artifacts(
    tenant_id,principal_id,device_id,project_ref,format,spec_version,sbom_sha256,
    signature_sha256,component_count,gate_decision,scan_summary
  ) VALUES (
    p_tenant_id,p_principal_id,p_device_id,p_project_ref,'CycloneDX',p_spec_version,
    p_sbom_sha256,p_signature_sha256,p_component_count,p_gate_decision,p_scan_summary
  ) RETURNING id INTO v_artifact_id;

  INSERT INTO public.global_sbom_components(
    tenant_id,artifact_id,purl,ecosystem,name,version,package_sha256,intel_status,intel_evidence_sha256
  )
  SELECT p_tenant_id,v_artifact_id,c.purl,c.ecosystem,c.name,c.version,c.package_sha256,
         c.intel_status,c.intel_evidence_sha256
  FROM jsonb_to_recordset(p_components) AS c(
    purl text, ecosystem text, name text, version text, package_sha256 text,
    intel_status text, intel_evidence_sha256 text
  );

  INSERT INTO public.global_execution_receipts(
    tenant_id,principal_id,device_id,action_type,action_payload_sha256,signature_sha256,
    decision,reason_code,policy_version
  ) VALUES (
    p_tenant_id,p_principal_id,p_device_id,'sbom_scan',p_sbom_sha256,p_signature_sha256,
    'BLOCKED',
    CASE WHEN p_gate_decision='BLOCKED' THEN 'supply_chain_compromise'
         ELSE 'supply_chain_review_required' END,
    'global-execution-gate-1'
  );

  RETURN v_artifact_id;
END;
$$;

REVOKE ALL ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb) TO service_role;
COMMENT ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb)
IS 'Atomically persists CycloneDX scan evidence and a fail-closed execution receipt after rechecking principal and fresh verified device state.';

     OR p_signature_sha256 IS NULL OR p_signature_sha256 !~ '^[a-f0-9]{64}
    RAISE EXCEPTION 'invalid_sbom_commit_payload';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_principals gp
    WHERE gp.id=p_principal_id AND gp.tenant_id=p_tenant_id AND gp.lifecycle_state='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'global_principal_not_active';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_device_attestations d
    WHERE d.id=p_device_id AND d.tenant_id=p_tenant_id AND d.principal_id=p_principal_id
      AND d.attestation_state='VERIFIED'
      AND d.last_attested_at >= v_now - interval '5 minutes'
      AND (d.valid_until IS NULL OR d.valid_until > v_now)
      AND d.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'verified_hardware_attestation_required';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_to_recordset(p_components) AS c(
      purl text, ecosystem text, name text, version text, package_sha256 text,
      intel_status text, intel_evidence_sha256 text
    )
    WHERE c.purl IS NULL OR c.ecosystem IS NULL OR c.name IS NULL OR c.version IS NULL
       OR c.intel_status NOT IN ('malicious','compromised','suspicious','unknown')
       OR (c.package_sha256 IS NOT NULL AND c.package_sha256 !~ '^[a-f0-9]{64}$')
       OR (c.intel_evidence_sha256 IS NOT NULL AND c.intel_evidence_sha256 !~ '^[a-f0-9]{64}$')
  ) THEN
    RAISE EXCEPTION 'invalid_sbom_component_payload';
  END IF;

  INSERT INTO public.global_sbom_artifacts(
    tenant_id,principal_id,device_id,project_ref,format,spec_version,sbom_sha256,
    signature_sha256,component_count,gate_decision,scan_summary
  ) VALUES (
    p_tenant_id,p_principal_id,p_device_id,p_project_ref,'CycloneDX',p_spec_version,
    p_sbom_sha256,p_signature_sha256,p_component_count,p_gate_decision,p_scan_summary
  ) RETURNING id INTO v_artifact_id;

  INSERT INTO public.global_sbom_components(
    tenant_id,artifact_id,purl,ecosystem,name,version,package_sha256,intel_status,intel_evidence_sha256
  )
  SELECT p_tenant_id,v_artifact_id,c.purl,c.ecosystem,c.name,c.version,c.package_sha256,
         c.intel_status,c.intel_evidence_sha256
  FROM jsonb_to_recordset(p_components) AS c(
    purl text, ecosystem text, name text, version text, package_sha256 text,
    intel_status text, intel_evidence_sha256 text
  );

  INSERT INTO public.global_execution_receipts(
    tenant_id,principal_id,device_id,action_type,action_payload_sha256,signature_sha256,
    decision,reason_code,policy_version
  ) VALUES (
    p_tenant_id,p_principal_id,p_device_id,'sbom_scan',p_sbom_sha256,p_signature_sha256,
    'BLOCKED',
    CASE WHEN p_gate_decision='BLOCKED' THEN 'supply_chain_compromise'
         ELSE 'supply_chain_review_required' END,
    'global-execution-gate-1'
  );

  RETURN v_artifact_id;
END;
$$;

REVOKE ALL ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb) TO service_role;
COMMENT ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb)
IS 'Atomically persists CycloneDX scan evidence and a fail-closed execution receipt after rechecking principal and fresh verified device state.';

     OR p_component_count IS NULL OR p_component_count < 0 OR p_component_count > 50000
     OR p_gate_decision IS NULL OR p_gate_decision NOT IN ('BLOCKED','REVIEW_REQUIRED')
     OR jsonb_typeof(p_scan_summary) IS DISTINCT FROM 'object'
     OR jsonb_typeof(p_components) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_components) <> p_component_count THEN
    RAISE EXCEPTION 'invalid_sbom_commit_payload';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_principals gp
    WHERE gp.id=p_principal_id AND gp.tenant_id=p_tenant_id AND gp.lifecycle_state='ACTIVE'
  ) THEN
    RAISE EXCEPTION 'global_principal_not_active';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.global_device_attestations d
    WHERE d.id=p_device_id AND d.tenant_id=p_tenant_id AND d.principal_id=p_principal_id
      AND d.attestation_state='VERIFIED'
      AND d.last_attested_at >= v_now - interval '5 minutes'
      AND (d.valid_until IS NULL OR d.valid_until > v_now)
      AND d.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'verified_hardware_attestation_required';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_to_recordset(p_components) AS c(
      purl text, ecosystem text, name text, version text, package_sha256 text,
      intel_status text, intel_evidence_sha256 text
    )
    WHERE c.purl IS NULL OR c.ecosystem IS NULL OR c.name IS NULL OR c.version IS NULL
       OR c.intel_status NOT IN ('malicious','compromised','suspicious','unknown')
       OR (c.package_sha256 IS NOT NULL AND c.package_sha256 !~ '^[a-f0-9]{64}$')
       OR (c.intel_evidence_sha256 IS NOT NULL AND c.intel_evidence_sha256 !~ '^[a-f0-9]{64}$')
  ) THEN
    RAISE EXCEPTION 'invalid_sbom_component_payload';
  END IF;

  INSERT INTO public.global_sbom_artifacts(
    tenant_id,principal_id,device_id,project_ref,format,spec_version,sbom_sha256,
    signature_sha256,component_count,gate_decision,scan_summary
  ) VALUES (
    p_tenant_id,p_principal_id,p_device_id,p_project_ref,'CycloneDX',p_spec_version,
    p_sbom_sha256,p_signature_sha256,p_component_count,p_gate_decision,p_scan_summary
  ) RETURNING id INTO v_artifact_id;

  INSERT INTO public.global_sbom_components(
    tenant_id,artifact_id,purl,ecosystem,name,version,package_sha256,intel_status,intel_evidence_sha256
  )
  SELECT p_tenant_id,v_artifact_id,c.purl,c.ecosystem,c.name,c.version,c.package_sha256,
         c.intel_status,c.intel_evidence_sha256
  FROM jsonb_to_recordset(p_components) AS c(
    purl text, ecosystem text, name text, version text, package_sha256 text,
    intel_status text, intel_evidence_sha256 text
  );

  INSERT INTO public.global_execution_receipts(
    tenant_id,principal_id,device_id,action_type,action_payload_sha256,signature_sha256,
    decision,reason_code,policy_version
  ) VALUES (
    p_tenant_id,p_principal_id,p_device_id,'sbom_scan',p_sbom_sha256,p_signature_sha256,
    'BLOCKED',
    CASE WHEN p_gate_decision='BLOCKED' THEN 'supply_chain_compromise'
         ELSE 'supply_chain_review_required' END,
    'global-execution-gate-1'
  );

  RETURN v_artifact_id;
END;
$$;

REVOKE ALL ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb) TO service_role;
COMMENT ON FUNCTION public.global_commit_sbom_scan(uuid,uuid,uuid,text,text,text,text,integer,text,jsonb,jsonb)
IS 'Atomically persists CycloneDX scan evidence and a fail-closed execution receipt after rechecking principal and fresh verified device state.';
