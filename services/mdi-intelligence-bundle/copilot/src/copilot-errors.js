export class CopilotRequestError extends Error {
  constructor() { super("invalid copilot request"); this.name = "CopilotRequestError"; this.statusCode = 400; }
}
export class CopilotAccessError extends Error {
  constructor() { super("thread access denied"); this.name = "CopilotAccessError"; this.statusCode = 403; }
}
export class CopilotDependencyError extends Error {
  constructor() { super("copilot dependency unavailable"); this.name = "CopilotDependencyError"; this.statusCode = 503; }
}
export function responseForCopilotError(error) {
  if (error instanceof CopilotRequestError) return { statusCode: 400, body: { error: error.message } };
  if (error instanceof CopilotAccessError) return { statusCode: 403, body: { error: "thread_access_denied" } };
  if (error instanceof CopilotDependencyError) return { statusCode: 503, body: { error: "copilot_dependency_unavailable" } };
  return { statusCode: 500, body: { error: "copilot_failed" } };
}
