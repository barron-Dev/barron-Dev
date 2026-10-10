-- Cyclothone compliance evidence freshness contract.
-- Idempotent and additive. Apply only through the approved migration/release process.
-- This reconciles ComplianceService.list_controls with the live schema audit.
ALTER TABLE IF EXISTS public.compliance_control_status
    ADD COLUMN IF NOT EXISTS evidence_valid_until timestamptz;

COMMENT ON COLUMN public.compliance_control_status.evidence_valid_until IS
    'Expiry timestamp for the evidence supporting this tenant/control status; NULL means no expiry has been established.';
