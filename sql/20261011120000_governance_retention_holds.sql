-- Retention governance configuration and legal-hold register.
-- This migration records policy and hold metadata only; it does not delete data or claim enforcement.
CREATE TABLE IF NOT EXISTS public.governance_retention_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    resource_type text NOT NULL CHECK (resource_type ~ '^[a-z][a-z0-9_.-]{1,79}$'),
    retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 36500),
    enabled boolean NOT NULL DEFAULT false,
    legal_basis text NOT NULL CHECK (length(legal_basis) BETWEEN 3 AND 1000),
    created_by uuid,
    updated_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, resource_type)
);
CREATE TABLE IF NOT EXISTS public.governance_legal_holds (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    resource_type text NOT NULL CHECK (resource_type ~ '^[a-z][a-z0-9_.-]{1,79}$'),
    resource_ref text NOT NULL CHECK (length(resource_ref) BETWEEN 8 AND 256),
    reason text NOT NULL CHECK (length(reason) BETWEEN 5 AND 2000),
    active boolean NOT NULL DEFAULT true,
    expires_at timestamptz,
    created_by uuid,
    released_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    CHECK (active = (released_at IS NULL))
);
CREATE INDEX IF NOT EXISTS governance_retention_policies_tenant_idx
    ON public.governance_retention_policies (tenant_id, resource_type);
CREATE INDEX IF NOT EXISTS governance_legal_holds_active_idx
    ON public.governance_legal_holds (tenant_id, resource_type, resource_ref)
    WHERE active;
ALTER TABLE public.governance_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governance_legal_holds ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.governance_retention_audit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_new jsonb;
    v_old jsonb;
    v_tenant_id uuid;
    v_actor uuid;
    v_id text;
    v_state_key text;
    v_action text;
BEGIN
    v_new := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END;
    v_old := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END;
    v_tenant_id := COALESCE((v_new->>'tenant_id')::uuid, (v_old->>'tenant_id')::uuid);
    v_actor := COALESCE((v_new->>'updated_by')::uuid, (v_new->>'created_by')::uuid,
                        (v_new->>'released_by')::uuid, (v_old->>'updated_by')::uuid,
                        (v_old->>'created_by')::uuid, (v_old->>'released_by')::uuid);
    v_id := COALESCE(v_new->>'id', v_old->>'id');
    v_state_key := CASE WHEN TG_TABLE_NAME = 'governance_legal_holds' THEN 'active' ELSE 'enabled' END;
    v_action := TG_TABLE_NAME || '.' || lower(TG_OP);
    INSERT INTO public.governance_audit_events
        (tenant_id, actor_user_id, action, resource_type, resource_id, before_state, after_state)
    VALUES (
        v_tenant_id, v_actor, v_action, TG_TABLE_NAME, v_id,
        CASE WHEN v_old IS NULL THEN NULL ELSE jsonb_build_object(v_state_key, v_old->v_state_key, 'expires_at', v_old->'expires_at') END,
        CASE WHEN v_new IS NULL THEN NULL ELSE jsonb_build_object(v_state_key, v_new->v_state_key, 'expires_at', v_new->'expires_at') END
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS governance_retention_policy_audit_trg ON public.governance_retention_policies;
CREATE TRIGGER governance_retention_policy_audit_trg
AFTER INSERT OR UPDATE ON public.governance_retention_policies
FOR EACH ROW EXECUTE FUNCTION public.governance_retention_audit();
DROP TRIGGER IF EXISTS governance_legal_hold_audit_trg ON public.governance_legal_holds;
CREATE TRIGGER governance_legal_hold_audit_trg
AFTER INSERT OR UPDATE ON public.governance_legal_holds
FOR EACH ROW EXECUTE FUNCTION public.governance_retention_audit();

COMMENT ON TABLE public.governance_retention_policies IS
    'Tenant retention-policy configuration. Configuration alone does not execute deletion or prove downstream enforcement.';
COMMENT ON TABLE public.governance_legal_holds IS
    'Tenant legal-hold registry. A hold only protects data when all relevant deletion workers enforce it.';
