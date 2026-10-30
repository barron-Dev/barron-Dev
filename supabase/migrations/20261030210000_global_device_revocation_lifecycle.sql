-- Device revocation lifecycle and append-only trust events.
CREATE TABLE IF NOT EXISTS public.global_device_trust_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 principal_id uuid NOT NULL,
 device_id uuid NOT NULL,
 event_type text NOT NULL CHECK (event_type IN ('DEVICE_REVOKED','ATTESTATION_EXPIRED','ATTESTATION_COMPROMISED','KEY_ROTATION_REQUIRED')),
 reason_code text NOT NULL CHECK (reason_code ~ '^[a-z0-9_]{3,80}$'),
 actor_fingerprint_sha256 text NOT NULL CHECK (actor_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
 evidence_sha256 text CHECK (evidence_sha256 IS NULL OR evidence_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES public.global_principals(tenant_id,id),
 FOREIGN KEY(tenant_id,device_id) REFERENCES public.global_device_attestations(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS global_device_trust_events_tenant_device_time_idx
 ON public.global_device_trust_events(tenant_id,device_id,created_at DESC);
ALTER TABLE public.global_device_trust_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.global_device_trust_events FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT ON public.global_device_trust_events TO service_role;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON public.global_device_trust_events FROM PUBLIC,anon,authenticated,service_role;

CREATE OR REPLACE FUNCTION public.prevent_global_device_unrevoke()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
   RAISE EXCEPTION 'revoked_device_requires_new_enrollment';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS global_device_no_unrevoke ON public.global_device_attestations;
CREATE TRIGGER global_device_no_unrevoke
 BEFORE UPDATE ON public.global_device_attestations
 FOR EACH ROW EXECUTE FUNCTION public.prevent_global_device_unrevoke();

CREATE OR REPLACE FUNCTION public.global_revoke_device(
 p_tenant_id uuid,p_principal_id uuid,p_device_id uuid,
 p_actor_fingerprint_sha256 text,p_reason_code text,p_evidence_sha256 text DEFAULT NULL
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE v_event uuid; v_fp text;
BEGIN
 IF p_actor_fingerprint_sha256 !~ '^[a-f0-9]{64}$'
    OR p_reason_code !~ '^[a-z0-9_]{3,80}$'
    OR (p_evidence_sha256 IS NOT NULL AND p_evidence_sha256 !~ '^[a-f0-9]{64}$') THEN
   RAISE EXCEPTION 'invalid_device_revocation_request';
 END IF;
 SELECT device_fingerprint INTO v_fp
 FROM public.global_device_attestations
 WHERE id=p_device_id AND tenant_id=p_tenant_id AND principal_id=p_principal_id
 FOR UPDATE;
 IF v_fp IS NULL THEN RAISE EXCEPTION 'global_device_not_found'; END IF;
 UPDATE public.global_device_attestations
 SET attestation_state='REVOKED',assurance_level='none',revoked_at=COALESCE(revoked_at,clock_timestamp()),valid_until=clock_timestamp()
 WHERE id=p_device_id AND tenant_id=p_tenant_id AND principal_id=p_principal_id;
 UPDATE public.global_device_challenges
 SET consumed_at=COALESCE(consumed_at,clock_timestamp())
 WHERE tenant_id=p_tenant_id AND principal_id=p_principal_id AND device_fingerprint=v_fp AND consumed_at IS NULL;
 INSERT INTO public.global_device_trust_events(
 tenant_id,principal_id,device_id,event_type,reason_code,actor_fingerprint_sha256,evidence_sha256
 ) VALUES(p_tenant_id,p_principal_id,p_device_id,'DEVICE_REVOKED',p_reason_code,p_actor_fingerprint_sha256,p_evidence_sha256)
 RETURNING id INTO v_event;
 RETURN v_event;
END $$;

REVOKE ALL ON FUNCTION public.global_revoke_device(uuid,uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_revoke_device(uuid,uuid,uuid,text,text,text) TO service_role;
COMMENT ON TABLE public.global_device_trust_events IS 'Append-only tenant-bound device trust lifecycle events; never stores raw operator identity.';
