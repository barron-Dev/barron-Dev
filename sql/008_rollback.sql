-- Sentinel rollback tracking and case-action realtime.
-- Depends on sql/007_unified_response.sql (case_actions, commands).

ALTER TABLE case_actions
    ADD COLUMN IF NOT EXISTS rolled_back_at timestamptz,
    ADD COLUMN IF NOT EXISTS rollback_command_id uuid REFERENCES commands(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS rollback_error text;

CREATE INDEX IF NOT EXISTS idx_case_actions_rollbackable
    ON case_actions(tenant_id, status)
    WHERE status = 'success' AND rolled_back_at IS NULL;

-- The frontend rollback control relies on UPDATE events for case_actions.
DO $$
BEGIN
    IF to_regclass('public.case_actions') IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
           FROM pg_publication_tables
           WHERE pubname = 'supabase_realtime'
             AND schemaname = 'public'
             AND tablename = 'case_actions'
       ) THEN
        EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE public.case_actions';
    END IF;
END;
$$;

ALTER TABLE case_actions REPLICA IDENTITY FULL;

-- Realtime SELECT authorization is tenant scoped, matching the existing
-- case_actions RLS policy from 007.
DROP POLICY IF EXISTS case_actions_select_realtime ON case_actions;
CREATE POLICY case_actions_select_realtime ON case_actions
    FOR SELECT TO authenticated
    USING (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);
