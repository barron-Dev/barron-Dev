import { CopilotAccessError } from "./copilot-errors.js";

/** Enforce actor ownership for service-role-backed Copilot threads. */
export function assertThreadOwnership(thread, { tenant_id, user_id, case_id = null }) {
  if (!thread || thread.tenant_id !== tenant_id || thread.actor_id !== user_id) {
    throw new CopilotAccessError();
  }
  if (case_id && thread.case_id !== case_id) throw new CopilotAccessError();
}
