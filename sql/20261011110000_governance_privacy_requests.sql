-- Cyclothone governance privacy-request register.
-- Tenant-scoped metadata only: do not store raw identity documents or request payloads here.
-- RLS is enabled; application access uses the privileged server client only after principal scope
-- checks and explicit tenant filters. No broad client policies are added by this migration.
CREATE TABLE IF NOT EXISTS public.governance_privacy_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    request_type text NOT NULL CHECK (request_type IN ('access','rectification','erasure','restriction','portability','objection')),
    subject_ref text NOT NULL CHECK (length(subject_ref) BETWEEN 8 AND 256),
    status text NOT NULL DEFAULT 'received' CHECK (status IN ('received','triage','in_progress','fulfilled','rejected')),
    request_summary text NOT NULL CHECK (length(request_summary) BETWEEN 1 AND 2000),
    due_at timestamptz,
    resolution_summary text,
    created_by uuid,
    updated_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    CHECK ((status IN ('fulfilled','rejected')) = (resolved_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS governance_privacy_requests_tenant_created_idx
    ON public.governance_privacy_requests (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS governance_privacy_requests_due_idx
    ON public.governance_privacy_requests (tenant_id, due_at)
    WHERE status NOT IN ('fulfilled','rejected');

CREATE TABLE IF NOT EXISTS public.governance_audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    actor_user_id uuid,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    before_state jsonb,
    after_state jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS governance_audit_events_tenant_time_idx
    ON public.governance_audit_events (tenant_id, occurred_at DESC);

ALTER TABLE public.governance_privacy_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governance_audit_events ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.governance_privacy_request_audit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_tenant_id uuid;
    v_actor uuid;
    v_action text;
BEGIN
    v_tenant_id := COALESCE(NEW.tenant_id, OLD.tenant_id);
    v_actor := COALESCE(NEW.updated_by, NEW.created_by, OLD.updated_by, OLD.created_by);
    v_action := CASE WHEN TG_OP = 'INSERT' THEN 'privacy_request.created' ELSE 'privacy_request.updated' END;
    INSERT INTO public.governance_audit_events
        (tenant_id, actor_user_id, action, resource_type, resource_id, before_state, after_state)
    VALUES (
        v_tenant_id, v_actor, v_action, 'privacy_request',
        COALESCE(NEW.id, OLD.id)::text,
        CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE jsonb_build_object('status', OLD.status, 'due_at', OLD.due_at, 'resolution_summary', OLD.resolution_summary) END,
        CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE jsonb_build_object('status', NEW.status, 'due_at', NEW.due_at, 'resolution_summary', NEW.resolution_summary) END
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS governance_privacy_request_audit_trg ON public.governance_privacy_requests;
CREATE TRIGGER governance_privacy_request_audit_trg
AFTER INSERT OR UPDATE ON public.governance_privacy_requests
FOR EACH ROW EXECUTE FUNCTION public.governance_privacy_request_audit();

COMMENT ON TABLE public.governance_privacy_requests IS
    'Tenant-scoped privacy request workflow metadata; subject_ref must be a non-reversible reference, not raw PII.';
COMMENT ON TABLE public.governance_audit_events IS
    'Append-only governance audit events emitted transactionally by governance triggers; no update/delete API is provided.';
