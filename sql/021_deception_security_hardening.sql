-- Sentinel Deception security hardening, migration 021.
-- Artifact bindings are security-sensitive control-plane state. They must not be
-- mutable by an ordinary tenant session because a broad UPDATE grant could alter
-- the target/rule/token metadata without passing the provisioning boundary.

DROP POLICY IF EXISTS deception_artifacts_tenant_update ON deception_artifacts;
REVOKE UPDATE ON deception_artifacts FROM authenticated;

-- Keep provisioning mutations behind the service-role path used by the
-- DeceptionEngine. Tenant sessions retain read/insert access from migration 019,
-- but cannot rewrite an existing canary's security bindings.

-- The autocase bridge already validates device and rule ownership at trigger time.
-- This index makes that validation efficient for larger tenant fleets.
CREATE INDEX IF NOT EXISTS idx_deception_artifacts_tenant_bindings
    ON deception_artifacts(tenant_id, device_id, auto_case_rule_id)
    WHERE enabled = true;
