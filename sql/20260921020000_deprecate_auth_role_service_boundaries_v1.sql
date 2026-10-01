-- Cyclothone security boundary reconciliation
-- Remove deprecated auth.role() from privileged SECURITY DEFINER functions while
-- preserving caller-role semantics via the signed JWT role claim.
--
-- These functions are owned by postgres, so current_user cannot be used to
-- distinguish the caller inside SECURITY DEFINER code.

DO $migration$
DECLARE
  r record;
  v_def text;
BEGIN
  FOR r IN
    SELECT
      p.oid,
      p.proname,
      pg_get_function_identity_arguments(p.oid) AS args,
      pg_get_functiondef(p.oid) AS definition
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.prokind = 'f'
      AND (
        (p.proname = 'add_customer_case_activity' AND pg_get_function_identity_arguments(p.oid) = 'p_case_id uuid, p_user_id uuid, p_message text')
        OR (p.proname = 'approve_customer_workspace' AND pg_get_function_identity_arguments(p.oid) = 'p_admission_id uuid, p_reviewer uuid, p_reason text')
        OR (p.proname = 'assign_customer_case' AND pg_get_function_identity_arguments(p.oid) = 'p_case_id uuid, p_operator_user_id uuid, p_assigned_operator uuid')
        OR (p.proname = 'open_customer_case' AND pg_get_function_identity_arguments(p.oid) = 'p_service_request_id uuid, p_operator_user_id uuid, p_category text, p_severity text')
        OR (p.proname = 'reject_customer_workspace' AND pg_get_function_identity_arguments(p.oid) = 'p_admission_id uuid, p_reviewer uuid, p_reason text')
        OR (p.proname = 'transition_customer_case' AND pg_get_function_identity_arguments(p.oid) = 'p_case_id uuid, p_operator_user_id uuid, p_status text, p_reason text')
        OR (p.proname = 'trust_enqueue_re_evaluation' AND pg_get_function_identity_arguments(p.oid) = 'p_subject_id uuid, p_event_type text, p_source_id uuid, p_source_hash text, p_reason text')
        OR (p.proname = 'trust_issue_public_key_ceremony' AND pg_get_function_identity_arguments(p.oid) = 'p_key_id text, p_purpose text, p_ttl_seconds integer')
        OR (p.proname = 'trust_register_public_key' AND pg_get_function_identity_arguments(p.oid) = 'p_key_id text, p_algorithm text, p_purpose text, p_public_key text, p_not_before timestamp with time zone, p_not_after timestamp with time zone, p_metadata jsonb')
        OR (p.proname = 'trust_register_public_key' AND pg_get_function_identity_arguments(p.oid) = 'p_key_id text, p_purpose text, p_public_key text, p_not_before timestamp with time zone, p_not_after timestamp with time zone, p_metadata jsonb')
        OR (p.proname = 'trust_revoke_public_key' AND pg_get_function_identity_arguments(p.oid) = 'p_key_id text')
        OR (p.proname = 'trust_update_certificate_status' AND pg_get_function_identity_arguments(p.oid) = 'p_certificate_id uuid, p_status text, p_reason text')
      )
  LOOP
    v_def := r.definition;
    v_def := replace(v_def, 'auth.role()', 'coalesce(auth.jwt()->>''role'','''')');
    v_def := replace(v_def, 'SET search_path TO ''public'', ''auth''', 'SET search_path TO ''public'', ''pg_catalog''');
    v_def := replace(v_def, 'SET search_path TO ''public''', 'SET search_path TO ''public'', ''pg_catalog''');
    EXECUTE v_def;
  END LOOP;
END
$migration$;

REVOKE EXECUTE ON FUNCTION public.add_customer_case_activity(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.approve_customer_workspace(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.assign_customer_case(uuid, uuid, uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.open_customer_case(uuid, uuid, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.reject_customer_workspace(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.transition_customer_case(uuid, uuid, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trust_enqueue_re_evaluation(uuid, text, uuid, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trust_issue_public_key_ceremony(text, text, integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trust_register_public_key(text, text, text, text, timestamptz, timestamptz, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trust_register_public_key(text, text, text, timestamptz, timestamptz, jsonb) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trust_revoke_public_key(text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.trust_update_certificate_status(uuid, text, text) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.add_customer_case_activity(uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.approve_customer_workspace(uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.assign_customer_case(uuid, uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION public.open_customer_case(uuid, uuid, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.reject_customer_workspace(uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.transition_customer_case(uuid, uuid, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.trust_enqueue_re_evaluation(uuid, text, uuid, text, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.trust_issue_public_key_ceremony(text, text, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.trust_register_public_key(text, text, text, timestamptz, timestamptz, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.trust_revoke_public_key(text) TO service_role;
GRANT EXECUTE ON FUNCTION public.trust_update_certificate_status(uuid, text, text) TO service_role;
