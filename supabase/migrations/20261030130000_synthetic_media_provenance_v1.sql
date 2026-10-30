-- Cyclothone Synthetic-Media Provenance Phase 1
-- Draft migration only. Do not apply to production until reviewed and explicitly approved.

CREATE TABLE IF NOT EXISTS public.c2pa_trust_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name text NOT NULL,
    policy_version text NOT NULL,
    trusted_root_pems text[] NOT NULL,
    trusted_root_sha256 text[] NOT NULL,
    is_active boolean NOT NULL DEFAULT false,
    source_uri text NOT NULL,
    source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) TO service_role;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.'),
('fr','VALID','Manifeste C2PA et chaîne de confiance vérifiés. Cela ne prouve ni l’identité des personnes représentées ni la véracité de la scène.'),
('fr','INVALID','La vérification de l’intégrité ou de la signature C2PA a échoué.'),
('fr','UNTRUSTED','La signature est valide, mais le certificat signataire n’est pas approuvé par cette politique.'),
('fr','MISSING_PROVENANCE','Aucune provenance C2PA trouvée. Cela ne signifie pas que le média est faux.'),
('fr','INDETERMINATE','La provenance C2PA n’a pas pu être analysée ou vérifiée de manière concluante.'),
('ja','VALID','C2PAマニフェストと設定された信頼チェーンを検証しました。映像内の人物の身元や場面の事実性を証明するものではありません。'),
('ja','INVALID','C2PAの完全性または署名の検証に失敗しました。'),
('ja','UNTRUSTED','署名は有効ですが、このポリシーでは署名証明書が信頼されていません。'),
('ja','MISSING_PROVENANCE','C2PAプロベナンスが見つかりません。メディアが偽物であることを意味しません。'),
('ja','INDETERMINATE','C2PAプロベナンスを確定的に解析または検証できませんでした。')
ON CONFLICT (locale, validation_state) DO NOTHING;
),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.')
ON CONFLICT (locale, validation_state) DO NOTHING;
),
    source_issued_at timestamptz NOT NULL,
    source_next_update timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.')
ON CONFLICT (locale, validation_state) DO NOTHING;


CREATE OR REPLACE FUNCTION public.activate_c2pa_trust_policy(
    p_policy_name text, p_policy_version text, p_trusted_root_pems text[],
    p_trusted_root_sha256 text[], p_source_uri text, p_source_commit text,
    p_source_sha256 text, p_source_issued_at timestamptz, p_source_next_update timestamptz
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF cardinality(p_trusted_root_pems) < 1 OR cardinality(p_trusted_root_pems) <> cardinality(p_trusted_root_sha256) THEN
        RAISE EXCEPTION 'invalid trust anchor set';
    END IF;
    IF p_source_next_update <= now() OR p_source_issued_at > now() THEN
        RAISE EXCEPTION 'trust list is not currently valid';
    END IF;
    UPDATE public.c2pa_trust_policies SET is_active = false WHERE is_active = true;
    INSERT INTO public.c2pa_trust_policies (
        policy_name, policy_version, trusted_root_pems, trusted_root_sha256,
        is_active, source_uri, source_commit, source_sha256, source_issued_at, source_next_update
    ) VALUES (
        p_policy_name, p_policy_version, p_trusted_root_pems, p_trusted_root_sha256,
        true, p_source_uri, p_source_commit, p_source_sha256, p_source_issued_at, p_source_next_update
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.activate_c2pa_trust_policy(text,text,text[],text[],text,text,text,timestamptz,timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.activate_c2pa_trust_policy(text,text,text[],text[],text,text,text,timestamptz,timestamptz) TO service_role;


CREATE OR REPLACE FUNCTION public.protect_c2pa_trust_policy()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'C2PA trust policies are immutable; deactivate and supersede instead';
    END IF;
    IF ROW(
        NEW.id, NEW.policy_name, NEW.policy_version, NEW.trusted_root_pems,
        NEW.trusted_root_sha256, NEW.source_uri, NEW.source_commit, NEW.source_sha256,
        NEW.source_issued_at, NEW.source_next_update, NEW.created_at, NEW.created_by
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.policy_name, OLD.policy_version, OLD.trusted_root_pems,
        OLD.trusted_root_sha256, OLD.source_uri, OLD.source_commit, OLD.source_sha256,
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
),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) TO service_role;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.'),
('fr','VALID','Manifeste C2PA et chaîne de confiance vérifiés. Cela ne prouve ni l’identité des personnes représentées ni la véracité de la scène.'),
('fr','INVALID','La vérification de l’intégrité ou de la signature C2PA a échoué.'),
('fr','UNTRUSTED','La signature est valide, mais le certificat signataire n’est pas approuvé par cette politique.'),
('fr','MISSING_PROVENANCE','Aucune provenance C2PA trouvée. Cela ne signifie pas que le média est faux.'),
('fr','INDETERMINATE','La provenance C2PA n’a pas pu être analysée ou vérifiée de manière concluante.'),
('ja','VALID','C2PAマニフェストと設定された信頼チェーンを検証しました。映像内の人物の身元や場面の事実性を証明するものではありません。'),
('ja','INVALID','C2PAの完全性または署名の検証に失敗しました。'),
('ja','UNTRUSTED','署名は有効ですが、このポリシーでは署名証明書が信頼されていません。'),
('ja','MISSING_PROVENANCE','C2PAプロベナンスが見つかりません。メディアが偽物であることを意味しません。'),
('ja','INDETERMINATE','C2PAプロベナンスを確定的に解析または検証できませんでした。')
ON CONFLICT (locale, validation_state) DO NOTHING;
),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.')
ON CONFLICT (locale, validation_state) DO NOTHING;
),
    source_issued_at timestamptz NOT NULL,
    source_next_update timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.')
ON CONFLICT (locale, validation_state) DO NOTHING;


CREATE OR REPLACE FUNCTION public.activate_c2pa_trust_policy(
    p_policy_name text, p_policy_version text, p_trusted_root_pems text[],
    p_trusted_root_sha256 text[], p_source_uri text, p_source_commit text,
    p_source_sha256 text, p_source_issued_at timestamptz, p_source_next_update timestamptz
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF cardinality(p_trusted_root_pems) < 1 OR cardinality(p_trusted_root_pems) <> cardinality(p_trusted_root_sha256) THEN
        RAISE EXCEPTION 'invalid trust anchor set';
    END IF;
    IF p_source_next_update <= now() OR p_source_issued_at > now() THEN
        RAISE EXCEPTION 'trust list is not currently valid';
    END IF;
    UPDATE public.c2pa_trust_policies SET is_active = false WHERE is_active = true;
    INSERT INTO public.c2pa_trust_policies (
        policy_name, policy_version, trusted_root_pems, trusted_root_sha256,
        is_active, source_uri, source_commit, source_sha256, source_issued_at, source_next_update
    ) VALUES (
        p_policy_name, p_policy_version, p_trusted_root_pems, p_trusted_root_sha256,
        true, p_source_uri, p_source_commit, p_source_sha256, p_source_issued_at, p_source_next_update
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.activate_c2pa_trust_policy(text,text,text[],text[],text,text,text,timestamptz,timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.activate_c2pa_trust_policy(text,text,text[],text[],text,text,text,timestamptz,timestamptz) TO service_role;


CREATE OR REPLACE FUNCTION public.protect_c2pa_trust_policy()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'C2PA trust policies are immutable; deactivate and supersede instead';
    END IF;
    IF ROW(
        NEW.id, NEW.policy_name, NEW.policy_version, NEW.trusted_root_pems,
        NEW.trusted_root_sha256, NEW.source_uri, NEW.source_commit, NEW.source_sha256,
        NEW.source_issued_at, NEW.source_next_update, NEW.created_at, NEW.created_by
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.policy_name, OLD.policy_version, OLD.trusted_root_pems,
        OLD.trusted_root_sha256, OLD.source_uri, OLD.source_commit, OLD.source_sha256,
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
),
    source_issued_at timestamptz NOT NULL,
    source_next_update timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) TO service_role;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.'),
('fr','VALID','Manifeste C2PA et chaîne de confiance vérifiés. Cela ne prouve ni l’identité des personnes représentées ni la véracité de la scène.'),
('fr','INVALID','La vérification de l’intégrité ou de la signature C2PA a échoué.'),
('fr','UNTRUSTED','La signature est valide, mais le certificat signataire n’est pas approuvé par cette politique.'),
('fr','MISSING_PROVENANCE','Aucune provenance C2PA trouvée. Cela ne signifie pas que le média est faux.'),
('fr','INDETERMINATE','La provenance C2PA n’a pas pu être analysée ou vérifiée de manière concluante.'),
('ja','VALID','C2PAマニフェストと設定された信頼チェーンを検証しました。映像内の人物の身元や場面の事実性を証明するものではありません。'),
('ja','INVALID','C2PAの完全性または署名の検証に失敗しました。'),
('ja','UNTRUSTED','署名は有効ですが、このポリシーでは署名証明書が信頼されていません。'),
('ja','MISSING_PROVENANCE','C2PAプロベナンスが見つかりません。メディアが偽物であることを意味しません。'),
('ja','INDETERMINATE','C2PAプロベナンスを確定的に解析または検証できませんでした。')
ON CONFLICT (locale, validation_state) DO NOTHING;
),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.')
ON CONFLICT (locale, validation_state) DO NOTHING;
),
    source_issued_at timestamptz NOT NULL,
    source_next_update timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid,
    CONSTRAINT c2pa_policy_roots_nonempty CHECK (
        cardinality(trusted_root_pems) > 0
        AND cardinality(trusted_root_sha256) > 0
        AND cardinality(trusted_root_pems) = cardinality(trusted_root_sha256)
    ),
    CONSTRAINT c2pa_policy_unique_version UNIQUE (policy_name, policy_version)
);
CREATE UNIQUE INDEX IF NOT EXISTS c2pa_one_active_policy ON public.c2pa_trust_policies (is_active) WHERE is_active;

CREATE TABLE IF NOT EXISTS public.media_provenance_receipts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    media_sha256 char(64) NOT NULL CHECK (media_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_store_sha256 char(64) CHECK (manifest_store_sha256 IS NULL OR manifest_store_sha256 ~ '^[0-9a-f]{64}$'),
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    signer_identity text,
    trust_policy_id uuid REFERENCES public.c2pa_trust_policies(id),
    trust_policy_version text,
    sdk_version text NOT NULL,
    raw_c2pa_report jsonb NOT NULL,
    ml_assessment jsonb,
    previous_receipt_hash char(64) NOT NULL CHECK (previous_receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_hash char(64) NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_signature text NOT NULL,
    signing_key_id text NOT NULL,
    signing_public_key text NOT NULL,
    signed_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_created ON public.media_provenance_receipts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS media_provenance_tenant_media ON public.media_provenance_receipts (tenant_id, media_sha256);

ALTER TABLE public.c2pa_trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_provenance_receipts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.c2pa_trust_policies FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.media_provenance_receipts FROM PUBLIC, anon, authenticated;
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
    p_tenant_id uuid, p_media_sha256 text, p_manifest_store_sha256 text,
    p_validation_state text, p_signer_identity text, p_trust_policy_id uuid,
    p_trust_policy_version text, p_sdk_version text, p_raw_c2pa_report jsonb,
    p_ml_assessment jsonb, p_previous_receipt_hash text, p_receipt_hash text,
    p_receipt_signature text, p_signing_key_id text, p_signing_public_key text,
    p_signed_payload jsonb
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_previous_hash text; v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF p_validation_state NOT IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE') THEN
        RAISE EXCEPTION 'invalid validation state';
    END IF;
    IF p_media_sha256 !~ '^[0-9a-f]{64}$' OR p_receipt_hash !~ '^[0-9a-f]{64}$'
       OR p_previous_receipt_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid SHA-256 value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 0));
    SELECT receipt_hash INTO v_previous_hash FROM public.media_provenance_receipts
     WHERE tenant_id = p_tenant_id ORDER BY created_at DESC, id DESC LIMIT 1;
    v_previous_hash := coalesce(v_previous_hash, repeat('0', 64));
    IF v_previous_hash <> p_previous_receipt_hash THEN
        RAISE EXCEPTION 'receipt chain head changed; retry with latest head' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.media_provenance_receipts (
        tenant_id, media_sha256, manifest_store_sha256, validation_state,
        signer_identity, trust_policy_id, trust_policy_version, sdk_version,
        raw_c2pa_report, ml_assessment, previous_receipt_hash, receipt_hash,
        receipt_signature, signing_key_id, signing_public_key, signed_payload
    ) VALUES (
        p_tenant_id, p_media_sha256, p_manifest_store_sha256, p_validation_state,
        p_signer_identity, p_trust_policy_id, p_trust_policy_version, p_sdk_version,
        p_raw_c2pa_report, p_ml_assessment, p_previous_receipt_hash, p_receipt_hash,
        p_receipt_signature, p_signing_key_id, p_signing_public_key, p_signed_payload
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.append_media_provenance_receipt(uuid,text,text,text,text,uuid,text,text,jsonb,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.provenance_i18n (
    locale text NOT NULL,
    validation_state text NOT NULL CHECK (validation_state IN ('VALID','INVALID','UNTRUSTED','MISSING_PROVENANCE','INDETERMINATE')),
    display_text text NOT NULL,
    PRIMARY KEY (locale, validation_state)
);
ALTER TABLE public.provenance_i18n ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.provenance_i18n FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON public.provenance_i18n TO service_role;
INSERT INTO public.provenance_i18n (locale, validation_state, display_text) VALUES
('en','VALID','C2PA manifest and configured trust chain verified. This does not establish depicted identity or factual truth.'),
('en','INVALID','C2PA integrity or signature validation failed.'),
('en','UNTRUSTED','Signature validation passed, but the signing certificate is not trusted by this policy.'),
('en','MISSING_PROVENANCE','No C2PA provenance manifest was found. This does not mean the media is fake.'),
('en','INDETERMINATE','C2PA provenance could not be conclusively parsed or validated.'),
('ar','VALID','تم التحقق من بيان C2PA وسلسلة الثقة وفق السياسة المحددة. ولا يثبت ذلك هوية الأشخاص الظاهرين أو صحة الوقائع.'),
('ar','INVALID','فشل التحقق من سلامة C2PA أو التوقيع.'),
('ar','UNTRUSTED','تم التحقق من التوقيع، لكن شهادة التوقيع غير موثوقة وفق هذه السياسة.'),
('ar','MISSING_PROVENANCE','لم يتم العثور على بيان مصدر C2PA. وهذا لا يعني أن الوسائط مزيفة.'),
('ar','INDETERMINATE','تعذر تحليل مصدر C2PA أو التحقق منه بشكل قاطع.')
ON CONFLICT (locale, validation_state) DO NOTHING;


CREATE OR REPLACE FUNCTION public.activate_c2pa_trust_policy(
    p_policy_name text, p_policy_version text, p_trusted_root_pems text[],
    p_trusted_root_sha256 text[], p_source_uri text, p_source_commit text,
    p_source_sha256 text, p_source_issued_at timestamptz, p_source_next_update timestamptz
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid;
BEGIN
    IF coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' THEN
        RAISE EXCEPTION 'service role required' USING ERRCODE = '42501';
    END IF;
    IF cardinality(p_trusted_root_pems) < 1 OR cardinality(p_trusted_root_pems) <> cardinality(p_trusted_root_sha256) THEN
        RAISE EXCEPTION 'invalid trust anchor set';
    END IF;
    IF p_source_next_update <= now() OR p_source_issued_at > now() THEN
        RAISE EXCEPTION 'trust list is not currently valid';
    END IF;
    UPDATE public.c2pa_trust_policies SET is_active = false WHERE is_active = true;
    INSERT INTO public.c2pa_trust_policies (
        policy_name, policy_version, trusted_root_pems, trusted_root_sha256,
        is_active, source_uri, source_commit, source_sha256, source_issued_at, source_next_update
    ) VALUES (
        p_policy_name, p_policy_version, p_trusted_root_pems, p_trusted_root_sha256,
        true, p_source_uri, p_source_commit, p_source_sha256, p_source_issued_at, p_source_next_update
    ) RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
REVOKE ALL ON FUNCTION public.activate_c2pa_trust_policy(text,text,text[],text[],text,text,text,timestamptz,timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.activate_c2pa_trust_policy(text,text,text[],text[],text,text,text,timestamptz,timestamptz) TO service_role;


CREATE OR REPLACE FUNCTION public.protect_c2pa_trust_policy()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'C2PA trust policies are immutable; deactivate and supersede instead';
    END IF;
    IF ROW(
        NEW.id, NEW.policy_name, NEW.policy_version, NEW.trusted_root_pems,
        NEW.trusted_root_sha256, NEW.source_uri, NEW.source_commit, NEW.source_sha256,
        NEW.source_issued_at, NEW.source_next_update, NEW.created_at, NEW.created_by
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.policy_name, OLD.policy_version, OLD.trusted_root_pems,
        OLD.trusted_root_sha256, OLD.source_uri, OLD.source_commit, OLD.source_sha256,
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
