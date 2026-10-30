-- Cover every composite foreign-key lookup added by Global Integrity v1.
CREATE INDEX IF NOT EXISTS global_device_challenges_tenant_principal_idx
  ON public.global_device_challenges(tenant_id,principal_id);
CREATE INDEX IF NOT EXISTS global_execution_receipts_tenant_principal_time_idx
  ON public.global_execution_receipts(tenant_id,principal_id,created_at DESC);
CREATE INDEX IF NOT EXISTS global_execution_receipts_tenant_device_idx
  ON public.global_execution_receipts(tenant_id,device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS global_execution_receipts_challenge_tenant_principal_idx
  ON public.global_execution_receipts(challenge_id,tenant_id,principal_id) WHERE challenge_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS global_sbom_artifacts_tenant_principal_time_idx
  ON public.global_sbom_artifacts(tenant_id,principal_id,created_at DESC);
CREATE INDEX IF NOT EXISTS global_sbom_artifacts_tenant_device_idx
  ON public.global_sbom_artifacts(tenant_id,device_id) WHERE device_id IS NOT NULL;
