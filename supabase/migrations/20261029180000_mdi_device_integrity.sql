-- SOURCE ONLY. Do not apply until live migration history/source reconciliation is complete.
-- Opaque tenant-scoped SHA-256 fingerprints only; never raw IMEI/serial/advertising IDs.
CREATE TABLE IF NOT EXISTS public.mdi_devices (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 device_key text NOT NULL CHECK (device_key ~ '^[a-f0-9]{64}$'),
 platform text NOT NULL CHECK (platform IN ('android','ios')),
 os_version text, app_version text,
 last_attestation text NOT NULL DEFAULT 'unknown' CHECK (last_attestation IN ('passed','failed','unavailable','unknown')),
 last_seen_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (tenant_id,device_key), UNIQUE (tenant_id,id)
);
CREATE INDEX IF NOT EXISTS mdi_devices_tenant_seen_idx ON public.mdi_devices (tenant_id,last_seen_at DESC);
CREATE TABLE IF NOT EXISTS public.mdi_device_threats (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, device_id uuid NOT NULL,
 threat_type text NOT NULL CHECK (threat_type IN ('root_indicator','jailbreak_indicator','debugger_detected','app_signature_mismatch','device_attestation_failed','known_malware_match','tls_validation_failure','dns_configuration_changed','arp_conflict_observed','developer_mode_enabled')),
 severity_level integer NOT NULL CHECK (severity_level BETWEEN 1 AND 5),
 disposition text NOT NULL CHECK (disposition IN ('threat_detected','human_review_required','partial_coverage','source_unavailable','unknown')),
 evidence_hash text NOT NULL CHECK (evidence_hash ~ '^[a-f0-9]{64}$'),
 journal_contract_id text, rule_version text NOT NULL, source_adapter_version text NOT NULL,
 observed_at timestamptz NOT NULL, persisted_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id,device_id) REFERENCES public.mdi_devices (tenant_id,id)
);
CREATE INDEX IF NOT EXISTS mdi_device_threats_tenant_observed_idx ON public.mdi_device_threats (tenant_id,observed_at DESC);
ALTER TABLE public.mdi_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mdi_device_threats ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.mdi_devices FROM anon,authenticated;
REVOKE ALL ON public.mdi_device_threats FROM anon,authenticated;
GRANT SELECT,INSERT,UPDATE ON public.mdi_devices TO service_role;
GRANT SELECT,INSERT ON public.mdi_device_threats TO service_role;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON public.mdi_device_threats FROM anon,authenticated,service_role;
-- No client-supplied tenant boundary, untrusted SECURITY DEFINER fan-out, or automatic wipe.
-- Trusted backend must resolve tenant from authenticated identity and verify signed contracts.
