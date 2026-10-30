-- Cyclothone Synthetic-Media Provenance Phase 1
-- Draft only: do not apply to production until explicitly approved.
-- Trust anchors are taken from a pinned CAI LoTE snapshot; they are not inferred from media metadata.

CREATE TABLE IF NOT EXISTS public.c2pa_trust_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name text NOT NULL,
    policy_version text NOT NULL,
    trusted_anchor_pems text[] NOT NULL,
    trusted_anchor_sha256 text[] NOT NULL,
    tsa_anchor_pems text[] NOT NULL,
    tsa_anchor_sha256 text[] NOT NULL,
    is_active boolean NOT NULL DEFAULT false,
    source_uri text NOT NULL,
    source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    source_issued_at timestamptz NOT NULL,
    source_next_update timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    CONSTRAINT c2pa_policy_anchors_nonempty CHECK (
        cardinality(trusted_anchor_pems) > 0
        AND cardinality(trusted_anchor_sha256) > 0
        AND cardinality(trusted_anchor_pems) = cardinality(trusted_anchor_sha256)
        AND cardinality(tsa_anchor_pems) > 0
        AND cardinality(tsa_anchor_sha256) > 0
        AND cardinality(tsa_anchor_pems) = cardinality(tsa_anchor_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);

CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy
    ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    source_job_id uuid NOT NULL UNIQUE,
    tenant_sequence bigint NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (
        manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'
    ),
    validation_state text NOT NULL CHECK (
        validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')
    ),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL CHECK (receipt_signature ~ '^[0-9a-f]{128}$'),
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    signed_payload_canonical text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT media_provenance_tenant_sequence_unique UNIQUE (tenant_id, tenant_sequence)
);

CREATE INDEX IF NOT EXISTS media_provenance_tenant_created
    ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media
    ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON public.c2pa_trust_policies TO service_role;
GRANT UPDATE (is_active) ON public.c2pa_trust_policies TO service_role;
GRANT SELECT, INSERT ON public.media_provenance_receipts TO service_role;

CREATE OR REPLACE FUNCTION public.reject_media_provenance_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'media provenance receipts are append-only';
END;
$$;
DROP TRIGGER IF EXISTS media_provenance_no_update ON public.media_provenance_receipts;
CREATE TRIGGER media_provenance_no_update
BEFORE UPDATE OR DELETE ON public.media_provenance_receipts
FOR EACH ROW EXECUTE FUNCTION public.reject_media_provenance_mutation();

CREATE OR REPLACE FUNCTION public.append_media_provenance_receipt(
    p_source_job_id uuid,
    p_tenant_id uuid,
    p_media_sha256 text,
    p_manifest_store_sha256 text,
    p_validation_state text,
    p_signer_identity text,
    p_trust_policy_id uuid,
    p_trust_policy_version text,
    p_sdk_version text,
    p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb,
    p_previous_receipt_hash text,
    p_receipt_hash text,
    p_receipt_signature text,
    p_signing_key_id text,
    p_signing_public_key text,
    p_signed_payload jsonb,
    p_signed_payload_canonical text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, extensions
AS $$
DECLARE
    v_previous_hash text;
    v_id uuid;
    v_sequence bigint;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_source_job_id IS NULL THEN
        RAISE EXCEPTION 'source job id required';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$'
       OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_receipt_signature !~ '^[0-9a-f]{128}$'
       OR coalesce(p_signing_key_id, '') = ''
       OR coalesce(p_signing_public_key, '') = '' THEN
        RAISE EXCEPTION 'invalid receipt cryptographic fields';
    END IF;
    IF p_signed_payload::text IS DISTINCT FROM p_signed_payload_canonical::jsonb::text
       OR encode(extensions.digest(convert_to(p_signed_payload_canonical, 'UTF8'), 'sha256'), 'hex') <> p_receipt_hash THEN
        RAISE EXCEPTION 'receipt payload hash or canonical JSON mismatch';
    END IF;
    IF p_signed_payload->>'source_job_id' IS DISTINCT FROM p_source_job_id::text
       OR p_signed_payload->>'tenant_id' IS DISTINCT FROM p_tenant_id::text
       OR p_signed_payload->>'media_sha256' IS DISTINCT FROM p_media_sha256
       OR p_signed_payload->>'manifest_store_sha256' IS DISTINCT FROM p_manifest_store_sha256
       OR p_signed_payload->>'validation_state' IS DISTINCT FROM p_validation_state
       OR p_signed_payload->>'signer_identity' IS DISTINCT FROM p_signer_identity
       OR p_signed_payload->>'trust_policy_id' IS DISTINCT FROM p_trust_policy_id::text
       OR p_signed_payload->>'trust_policy_version' IS DISTINCT FROM p_trust_policy_version
       OR p_signed_payload->>'sdk_version' IS DISTINCT FROM p_sdk_version
       OR p_signed_payload->>'previous_receipt_hash' IS DISTINCT FROM p_previous_receipt_hash
       OR p_signed_payload->'ml_assessment' IS DISTINCT FROM p_ml_assessment
       OR p_signed_payload->>'created_at' IS NULL THEN
        RAISE EXCEPTION 'signed receipt payload does not match receipt fields';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT id INTO v_id
      FROM public.media_provenance_receipts
     WHERE source_job_id = p_source_job_id AND tenant_id = p_tenant_id;
    IF FOUND THEN
        RETURN v_id;
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.media_provenance_receipts
         WHERE source_job_id = p_source_job_id
    ) THEN
        RAISE EXCEPTION 'source job tenant mismatch' USING ERRCODE = '42501';
    END IF;
    SELECT coalesce(max(tenant_sequence), 0) + 1
      INTO v_sequence
      FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id;
    SELECT receipt_hash INTO v_previous_hash
      FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id
     ORDER BY tenant_sequence DESC
     LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;

    INSERT INTO public.media_provenance_receipts (
        source_job_id, tenant_id, tenant_sequence, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload,
        signed_payload_canonical, created_at
    ) VALUES (
        p_source_job_id, p_tenant_id, v_sequence, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload,
        p_signed_payload_canonical, (p_signed_payload->>'created_at')::timestamptz
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;

REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(
    uuid,uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb,text
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.append_media_provenance_receipt(
    uuid,uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb,text
) TO service_role;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (
        validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')
    ),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;

INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest, hard bindings, signature and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','C2PA signature and integrity are valid, but the signer is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA والروابط والتوقيع وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','التوقيع وسلامة المحتوى صحيحان، لكن جهة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.'),
('fr','VALID','Manifeste C2PA, liaisons, signature et chaîne de confiance vérifiés. Cela ne prouve ni l’identité des personnes représentées ni la véracité de la scène.'),
('fr','INVALID','La vérification de l’intégrité ou de la signature C2PA a échoué.'),
('fr','UNTRUSTED','La signature et l’intégrité sont valides, mais le signataire n’est pas approuvé par cette politique.'),
('fr','MISSING_PROVENANCE','Aucune provenance C2PA trouvée. Cela ne signifie pas que le média est faux.'),
('fr','INDETERMINATE','La provenance C2PA n’a pas pu être analysée ou vérifiée de manière concluante.'),
('ja','VALID','C2PAマニフェスト、ハードバインディング、署名、および設定された信頼チェーンを検証しました。映像内の人物の身元や場面の事実性を証明するものではありません。'),
('ja','INVALID','C2PAの完全性または署名の検証に失敗しました。'),
('ja','UNTRUSTED','署名と完全性は有効ですが、このポリシーでは署名者が信頼されていません。'),
('ja','MISSING_PROVENANCE','C2PAプロベナンスが見つかりません。メディアが偽物であることを意味しません。'),
('ja','INDETERMINATE','C2PAプロベナンスを確定的に解析または検証できませんでした.')
ON CONFLICT (locale, validation_state) DO NOTHING;

CREATE OR REPLACE FUNCTION public.activate_c2pa_trust_policy(
    p_policy_name text,
    p_policy_version text,
    p_trusted_anchor_pems text[],
    p_trusted_anchor_sha256 text[],
    p_tsa_anchor_pems text[],
    p_tsa_anchor_sha256 text[],
    p_source_uri text,
    p_source_commit text,
    p_source_sha256 text,
    p_source_issued_at timestamptz,
    p_source_next_update timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF cardinality(p_trusted_anchor_pems) < 1
       OR cardinality(p_trusted_anchor_pems) <> cardinality(p_trusted_anchor_sha256)
       OR cardinality(p_tsa_anchor_pems) < 1
       OR cardinality(p_tsa_anchor_pems) <> cardinality(p_tsa_anchor_sha256) THEN
        RAISE EXCEPTION 'invalid manifest or TSA trust anchor set';
    END IF;
    IF p_source_commit !~ '^[0-9a-f]{40}$'
       OR p_source_sha256 !~ '^[0-9a-f]{64}$'
       OR p_source_next_update <= now()
       OR p_source_issued_at > now() THEN
        RAISE EXCEPTION 'trust list source metadata is invalid or expired';
    END IF;
    UPDATE public.c2pa_trust_policies SET is_active = false WHERE is_active = true;
    INSERT INTO public.c2pa_trust_policies (
        policy_name, policy_version, trusted_anchor_pems, trusted_anchor_sha256,
        tsa_anchor_pems, tsa_anchor_sha256, is_active, source_uri, source_commit,
        source_sha256, source_issued_at, source_next_update
    ) VALUES (
        p_policy_name, p_policy_version, p_trusted_anchor_pems, p_trusted_anchor_sha256,
        p_tsa_anchor_pems, p_tsa_anchor_sha256, true, p_source_uri, p_source_commit,
        p_source_sha256, p_source_issued_at, p_source_next_update
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.activate_c2pa_trust_policy(
    text,text,text[],text[],text[],text[],text,text,text,timestamptz,timestamptz
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.activate_c2pa_trust_policy(
    text,text,text[],text[],text[],text[],text,text,text,timestamptz,timestamptz
) TO service_role;

CREATE OR REPLACE FUNCTION public.protect_c2pa_trust_policy()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'C2PA trust policies are immutable; deactivate and supersede instead';
    END IF;
    IF ROW(
        NEW.id, NEW.policy_name, NEW.policy_version, NEW.trusted_anchor_pems,
        NEW.trusted_anchor_sha256, NEW.tsa_anchor_pems, NEW.tsa_anchor_sha256,
        NEW.source_uri, NEW.source_commit, NEW.source_sha256,
        NEW.source_issued_at, NEW.source_next_update, NEW.created_at, NEW.created_by
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.policy_name, OLD.policy_version, OLD.trusted_anchor_pems,
        OLD.trusted_anchor_sha256, OLD.tsa_anchor_pems, OLD.tsa_anchor_sha256,
        OLD.source_uri, OLD.source_commit, OLD.source_sha256,
        OLD.source_issued_at, OLD.source_next_update, OLD.created_at, OLD.created_by
    ) THEN
        RAISE EXCEPTION 'C2PA trust policy content is immutable';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS c2pa_trust_policy_immutable ON public.c2pa_trust_policies;
CREATE TRIGGER c2pa_trust_policy_immutable
BEFORE UPDATE OR DELETE ON public.c2pa_trust_policies
FOR EACH ROW EXECUTE FUNCTION public.protect_c2pa_trust_policy();


-- Private staging storage and durable asynchronous verification jobs.
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('cyclothone-provenance-staging', 'cyclothone-provenance-staging', false, 262144000)
ON CONFLICT (id) DO UPDATE
SET public = false, file_size_limit = EXCLUDED.file_size_limit;

CREATE TABLE IF NOT EXISTS public.media_provenance_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    requested_by uuid,
    object_path text NOT NULL UNIQUE,
    original_filename text NOT NULL,
    content_type text,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','processing','succeeded','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 5),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_expires_at timestamptz,
    receipt_id uuid REFERENCES public.media_provenance_receipts(id),
    validation_state text CHECK (
        validation_state IS NULL OR validation_state IN (
            'VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE'
        )
    ),
    result_json jsonb,
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS media_provenance_jobs_queue
    ON public.media_provenance_jobs (status, available_at, created_at);
CREATE INDEX IF NOT EXISTS media_provenance_jobs_tenant_created
    ON public.media_provenance_jobs (tenant_id, created_at DESC);

ALTER TABLE public.media_provenance_jobs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.media_provenance_jobs FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.media_provenance_jobs TO service_role;

CREATE OR REPLACE FUNCTION public.claim_media_provenance_job()
RETURNS SETOF public.media_provenance_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;

    UPDATE public.media_provenance_jobs
       SET status = 'failed',
           failure_code = 'worker_attempts_exhausted',
           lease_expires_at = NULL,
           updated_at = now(),
           completed_at = now()
     WHERE status = 'processing'
       AND lease_expires_at < now()
       AND attempts >= max_attempts;

    RETURN QUERY
    WITH candidate AS (
        SELECT id
          FROM public.media_provenance_jobs
         WHERE (
             (status = 'queued' AND available_at <= now())
             OR (status = 'processing' AND lease_expires_at < now() AND attempts < max_attempts)
         )
         ORDER BY created_at
         FOR UPDATE SKIP LOCKED
         LIMIT 1
    )
    UPDATE public.media_provenance_jobs AS job
       SET status = 'processing',
           attempts = job.attempts + 1,
           lease_expires_at = now() + interval '30 minutes',
           updated_at = now(),
           failure_code = NULL
      FROM candidate
     WHERE job.id = candidate.id
    RETURNING job.*;
END;
$$;
REVOKE ALL ON FUNCTION public.claim_media_provenance_job() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_media_provenance_job() TO service_role;
