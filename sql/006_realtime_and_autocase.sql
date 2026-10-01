-- Sentinel realtime + detection -> case automation
-- This migration is intentionally idempotent because the live Supabase project may
-- already have these objects applied out-of-band.

-- ============================================================
-- SUPABASE REALTIME PUBLICATION
-- ============================================================
DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['detections','commands','devices','crime_cases','playbook_runs'] LOOP
        IF to_regclass(format('public.%I', tbl)) IS NOT NULL
           AND NOT EXISTS (
               SELECT 1
               FROM pg_publication_tables
               WHERE pubname = 'supabase_realtime'
                 AND schemaname = 'public'
                 AND tablename = tbl
           ) THEN
            EXECUTE format('alter publication supabase_realtime add table public.%I', tbl);
        END IF;
    END LOOP;
END;
$$;

DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['detections','commands','devices','crime_cases','playbook_runs'] LOOP
        IF to_regclass(format('public.%I', tbl)) IS NOT NULL THEN
            EXECUTE format('alter table public.%I replica identity full', tbl);
        END IF;
    END LOOP;
END;
$$;

-- ============================================================
-- AUTO-CASE RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS auto_case_rules (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    priority        integer NOT NULL DEFAULT 100,
    trigger         jsonb NOT NULL,
    category        text NOT NULL CHECK (category IN (
        'ransomware','phishing','bec','fraud','sextortion',
        'investment_scam','romance_scam','tech_support',
        'identity_theft','data_breach','extortion','other'
    )),
    severity        text NOT NULL DEFAULT 'medium'
                    CHECK (severity IN ('low','medium','high','critical')),
    evidence_fields text[] NOT NULL DEFAULT ARRAY['reasons','evidence'],
    created_by      uuid REFERENCES auth.users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auto_case_rules_tenant
    ON auto_case_rules(tenant_id, enabled, priority);

ALTER TABLE auto_case_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS auto_case_rules_tenant ON auto_case_rules;
CREATE POLICY auto_case_rules_tenant ON auto_case_rules
    FOR ALL TO authenticated
    USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)
    WITH CHECK (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

-- ============================================================
-- DETECTION -> CASE LINK + PROCESSING WATERMARK
-- ============================================================
ALTER TABLE crime_cases
    ADD COLUMN IF NOT EXISTS detection_ids uuid[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_cases_detection_ids
    ON crime_cases USING gin(detection_ids);

ALTER TABLE detections
    ADD COLUMN IF NOT EXISTS processed_by_autocase boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_detections_autocase
    ON detections(created_at)
    WHERE processed_by_autocase = false;

-- ============================================================
-- TRANSACTIONAL CASE CREATION RPC
-- The advisory lock makes the detection idempotency check race-safe when
-- multiple automation workers see the same detection concurrently.
-- ============================================================
CREATE OR REPLACE FUNCTION create_case_from_detection(
    p_tenant_id uuid,
    p_rule_id uuid,
    p_detection_id uuid,
    p_category text,
    p_severity text,
    p_title text,
    p_summary text,
    p_evidence jsonb,
    p_device_id uuid,
    p_actor text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_case_id uuid;
    v_case_number text;
BEGIN
    IF p_tenant_id IS NULL OR p_rule_id IS NULL OR p_detection_id IS NULL THEN
        RAISE EXCEPTION 'tenant, rule, and detection identifiers are required';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM auto_case_rules
        WHERE id = p_rule_id
          AND tenant_id = p_tenant_id
          AND enabled = true
    ) THEN
        RAISE EXCEPTION 'auto-case rule is missing, disabled, or belongs to another tenant';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM detections
        WHERE id = p_detection_id
          AND tenant_id = p_tenant_id
    ) THEN
        RAISE EXCEPTION 'detection does not belong to tenant';
    END IF;

    -- Stable advisory lock scoped to this detection, preventing duplicate cases
    -- across concurrent workers without introducing a global lock.
    PERFORM pg_advisory_xact_lock(hashtextextended(p_detection_id::text, 0));

    SELECT id
      INTO v_case_id
      FROM crime_cases
     WHERE tenant_id = p_tenant_id
       AND p_detection_id = ANY(detection_ids)
     ORDER BY created_at
     LIMIT 1
     FOR UPDATE;

    IF v_case_id IS NOT NULL THEN
        RETURN v_case_id;
    END IF;

    SELECT next_case_number(p_tenant_id) INTO v_case_number;

    INSERT INTO crime_cases (
        tenant_id, case_number, title, category, severity, status,
        summary, device_id, evidence, detection_ids
    ) VALUES (
        p_tenant_id, v_case_number, p_title, p_category, p_severity, 'open',
        p_summary, p_device_id, p_evidence, ARRAY[p_detection_id]
    )
    RETURNING id INTO v_case_id;

    INSERT INTO case_timeline (case_id, actor, kind, payload)
    VALUES (
        v_case_id, p_actor, 'auto_created',
        jsonb_build_object(
            'rule_id', p_rule_id,
            'detection_id', p_detection_id,
            'category', p_category,
            'severity', p_severity
        )
    );

    RETURN v_case_id;
END;
$$;

REVOKE ALL ON FUNCTION create_case_from_detection(
    uuid, uuid, uuid, text, text, text, text, jsonb, uuid, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_case_from_detection(
    uuid, uuid, uuid, text, text, text, text, jsonb, uuid, text
) TO service_role;

-- ============================================================
-- REALTIME SELECT POLICIES
-- Realtime evaluates table SELECT authorization for authenticated users.
-- ============================================================
DO $$
BEGIN
    IF to_regclass('public.detections') IS NOT NULL THEN
        EXECUTE 'DROP POLICY IF EXISTS detections_select ON detections';
        EXECUTE $$CREATE POLICY detections_select ON detections
            FOR SELECT TO authenticated
            USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)$$;
    END IF;
    IF to_regclass('public.commands') IS NOT NULL THEN
        EXECUTE 'DROP POLICY IF EXISTS commands_select ON commands';
        EXECUTE $$CREATE POLICY commands_select ON commands
            FOR SELECT TO authenticated
            USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)$$;
    END IF;
    IF to_regclass('public.crime_cases') IS NOT NULL THEN
        EXECUTE 'DROP POLICY IF EXISTS cases_select ON crime_cases';
        EXECUTE $$CREATE POLICY cases_select ON crime_cases
            FOR SELECT TO authenticated
            USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)$$;
    END IF;
    IF to_regclass('public.playbook_runs') IS NOT NULL THEN
        EXECUTE 'DROP POLICY IF EXISTS playbook_runs_select ON playbook_runs';
        EXECUTE $$CREATE POLICY playbook_runs_select ON playbook_runs
            FOR SELECT TO authenticated
            USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid)$$;
    END IF;
END;
$$;
