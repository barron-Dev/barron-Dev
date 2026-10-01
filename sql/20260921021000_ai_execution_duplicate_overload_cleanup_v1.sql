-- Consolidate legacy AI execution overloads into the canonical, run-bound interfaces.
-- The removed overloads were service-role-only and had weaker execution binding:
-- ai_security_admit lacked action_hash enforcement and
-- claim_ai_execution_envelope lacked run binding.

DROP FUNCTION public.ai_security_admit(uuid, uuid, text, text, text, text, boolean, text, text, text, text);
DROP FUNCTION public.claim_ai_execution_envelope(uuid, text, text, timestamptz);
