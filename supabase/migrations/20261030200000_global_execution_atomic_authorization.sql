-- Atomic global execution decision: consume challenge, re-check live trust state, and append receipt in one transaction.
-- Signature verification remains in the API cryptographic boundary; this RPC receives only its boolean result.
CREATE OR REPLACE FUNCTION public.global_authorize_execution_atomic(
 p_tenant_id uuid,
 p_principal_id uuid,
 p_device_id uuid,
 p_challenge_id uuid,
 p_device_fingerprint text,
 p_context_sha256 text,
 p_nonce text,
 p_action_type text,
 p_payload_sha256 text,
 p_signature_sha256 text,
 p_signature_valid boolean
) RETURNS TABLE(decision text, reason_code text, receipt_id uuid)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
DECLARE
 v_now timestamptz := clock_timestamp();
 v_device public.global_device_attestations%ROWTYPE;
 v_principal_state text;
 v_challenge_consumed boolean := false;
 v_reason text;
 v_receipt uuid;
BEGIN
 SELECT lifecycle_state INTO v_principal_state
 FROM public.global_principals
 WHERE id=p_principal_id AND tenant_id=p_tenant_id;

 SELECT d.* INTO v_device
 FROM public.global_device_attestations d
 JOIN public.devices pd ON pd.id=d.platform_device_id AND pd.tenant_id=d.tenant_id
 WHERE d.id=p_device_id AND d.tenant_id=p_tenant_id AND d.principal_id=p_principal_id
   AND d.device_fingerprint=p_device_fingerprint AND pd.status='active'
 FOR UPDATE OF d;

 IF p_signature_valid AND v_device.id IS NOT NULL THEN
   UPDATE public.global_device_challenges
   SET consumed_at=v_now
   WHERE id=p_challenge_id AND tenant_id=p_tenant_id AND principal_id=p_principal_id
     AND device_fingerprint=p_device_fingerprint AND purpose='sensitive_action'
     AND context_sha256=p_context_sha256 AND nonce=p_nonce
     AND consumed_at IS NULL AND expires_at>v_now;
   v_challenge_consumed := FOUND;
 END IF;

 IF v_principal_state IS DISTINCT FROM 'ACTIVE' THEN
   v_reason := 'global_principal_not_active';
 ELSIF v_device.id IS NULL THEN
   v_reason := 'device_not_active_or_not_registered';
 ELSIF NOT p_signature_valid OR NOT v_challenge_consumed THEN
   v_reason := 'signature_invalid_or_challenge_replayed';
 ELSIF v_device.attestation_state <> 'VERIFIED'
    OR v_device.assurance_level NOT IN ('hardware_attested','workload_attested')
    OR v_device.last_attested_at IS NULL
    OR v_device.last_attested_at > v_now
    OR v_device.last_attested_at < v_now - interval '5 minutes'
    OR (v_device.valid_until IS NOT NULL AND v_device.valid_until <= v_now)
    OR v_device.revoked_at IS NOT NULL THEN
   v_reason := 'hardware_attestation_missing_or_stale';
 ELSE
   v_reason := 'authorized';
 END IF;

 INSERT INTO public.global_execution_receipts(
   tenant_id,principal_id,device_id,challenge_id,action_type,action_payload_sha256,
   signature_sha256,decision,reason_code
 ) VALUES (
   p_tenant_id,p_principal_id,p_device_id,p_challenge_id,p_action_type,p_payload_sha256,
   p_signature_sha256,CASE WHEN v_reason='authorized' THEN 'AUTHORIZED' ELSE 'BLOCKED' END,v_reason
 ) RETURNING id INTO v_receipt;

 RETURN QUERY SELECT CASE WHEN v_reason='authorized' THEN 'AUTHORIZED' ELSE 'BLOCKED' END,v_reason,v_receipt;
END;
$$;

REVOKE ALL ON FUNCTION public.global_authorize_execution_atomic(uuid,uuid,uuid,uuid,text,text,text,text,text,text,boolean) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.global_authorize_execution_atomic(uuid,uuid,uuid,uuid,text,text,text,text,text,text,boolean) TO service_role;
COMMENT ON FUNCTION public.global_authorize_execution_atomic(uuid,uuid,uuid,uuid,text,text,text,text,text,text,boolean)
IS 'Atomic sensitive-action gate: consumes a one-time challenge, rechecks active tenant device and fresh hardware attestation, and writes immutable decision receipt.';
