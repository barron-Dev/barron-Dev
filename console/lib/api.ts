export type ConsoleOverview = {
  generated_at: string;
  window: "24h";
  agents: { total: number };
  threats: { last_24h: number; previous_24h: number; delta_percent: number | null };
  critical: { count: number };
  uptime_percent: number | null;
  response_p95_ms: number | null;
  coverage: Record<string, { observed: number } | null>;
  feed: Array<{
    id: string;
    device_id: string | null;
    detector: string;
    score: number | null;
    verdict: string | null;
    reasons: string[] | null;
    created_at: string;
    mitre_technique?: string | null;
  }>;
};

const DEFAULT_API_BASE = "https://cyclothone-api-production.up.railway.app";

function resolveApiBase() {
  const configured = (process.env.NEXT_PUBLIC_CYCLOTHONE_API_URL ?? "").trim().replace(/\/$/, "");
  if (!configured) return DEFAULT_API_BASE;

  try {
    const configuredUrl = new URL(configured);
    if (typeof window !== "undefined" && configuredUrl.origin === window.location.origin) {
      return DEFAULT_API_BASE;
    }
  } catch {
    return DEFAULT_API_BASE;
  }

  return configured;
}

const API_BASE = resolveApiBase();
let accessToken: string | null = null;

if (typeof window !== "undefined") accessToken = sessionStorage.getItem("cyclothone_access_token");

export function setApiToken(token: string) {
  accessToken = token.trim() || null;
  if (typeof window !== "undefined") {
    if (accessToken) sessionStorage.setItem("cyclothone_access_token", accessToken);
    else sessionStorage.removeItem("cyclothone_access_token");
  }
}

export function clearApiToken() {
  accessToken = null;
  if (typeof window !== "undefined") sessionStorage.removeItem("cyclothone_access_token");
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });

  const contentType = response.headers.get("content-type") ?? "";
  const raw = await response.text();
  let payload: unknown = null;
  if (raw) {
    try { payload = JSON.parse(raw); } catch { payload = null; }
  }

  if (!response.ok) {
    const detail = payload && typeof payload === "object"
      ? (payload as Record<string, unknown>).detail ?? (payload as Record<string, unknown>).message
      : null;
    const detailText = typeof detail === "string"
      ? detail
      : detail && typeof detail === "object"
        ? JSON.stringify(detail)
        : "";
    const message =
      response.status === 401 ? "Authentication required" :
      response.status === 403 ? (detailText || "Required API scope is missing") :
      detailText || `Backend request failed (HTTP ${response.status})`;
    throw new Error(message);
  }

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("Backend returned a non-JSON response");
  }

  if (payload === null) throw new Error("Backend returned invalid JSON");
  return payload as T;
}

export function getOverview() {
  return apiFetch<ConsoleOverview>("/api/v1/console/overview");
}

export type ModelRouteRequest = {
  workload_layer: string;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  required_capabilities?: string[];
  mission_id?: string;
  mission_version?: number;
  mission_hash?: string;
};

export type ModelRoute = {
  route_id: string;
  route_name: string;
  workload_layer: string;
  model_id: string;
  model_version: number;
  provider_id: string;
  priority: number;
  max_risk_level: string;
  capabilities: string[];
  constraints: Record<string, unknown>;
  tenant_specific: boolean;
};

export function resolveModelRoute(body: ModelRouteRequest) {
  return apiFetch<ModelRoute>("/api/v1/ai/route", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export type AIRunStartRequest = ModelRouteRequest & {
  mission_id: string;
  mission_version: number;
  mission_hash: string;
  idempotency_token: string;
  trace_id?: string;
  correlation_id?: string;
};

export type AIRunStart = {
  run_id: string;
  tenant_id: string;
  agent_id: string;
  agent_version: number;
  mission_id: string;
  mission_version: number;
  mission_hash: string;
  model_id: string;
  model_version: number;
  provider_id: string;
  provider_binding_version: number;
  run_state: string;
  request_fingerprint: string;
};

export function startAIRun(body: AIRunStartRequest) {
  return apiFetch<AIRunStart>("/api/v1/ai/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export type AIRunExecution = {
  run_id: string;
  provider_id: string;
  model_id: string;
  run_state: string;
  output_text: string;
  usage: {
    tokens_in: number;
    tokens_out: number;
    tokens_cached: number;
    latency_ms: number;
    cost_usd: string;
  };
};

export function executeAIRun(runId: string, input_text: string) {
  return apiFetch<AIRunExecution>(`/api/v1/ai/run/${encodeURIComponent(runId)}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input_text }),
  });
}


export type AdmissionRecord = {
  id: string;
  organization_id: string;
  requested_by: string;
  status: string;
  assurance_level: string | null;
  submitted_at: string | null;
  reviewed_at: string | null;
  organization: {
    id: string;
    owner_user_id: string;
    tenant_id: string | null;
    organization_type: string;
    legal_name: string;
    country_code: string | null;
    website_domain: string | null;
    registration_number: string | null;
    verification_status: string;
    admission_status: string;
  } | null;
  verifications: Array<{
    id: string;
    verification_type: string;
    status: string;
    provider: string | null;
    reference: string | null;
    submitted_at: string | null;
    verified_at: string | null;
  }>;
  service_requests: Array<{
    id: string;
    service_key: string;
    urgency: string;
    description: string;
    status: string;
    created_at: string;
  }>;
};

export function getAdmissions() {
  return apiFetch<{ admissions: AdmissionRecord[] }>("/api/v1/customer/admissions");
}

export function decideAdmission(admissionId: string, decision: "approve" | "reject", reason?: string) {
  return apiFetch<{ status: string; tenant_id?: string; organization_id?: string }>(
    `/api/v1/customer/admissions/${encodeURIComponent(admissionId)}/${decision}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: reason?.trim() || null }),
    },
  );
}


export type CustomerOrganization = {
  id: string;
  tenant_id: string | null;
  organization_type: string;
  legal_name: string;
  country_code: string | null;
  website_domain: string | null;
  registration_number: string | null;
  verification_status: string;
  admission_status: string;
  created_at: string;
  updated_at: string;
};

export type CustomerServiceRequest = {
  id: string;
  organization_id: string;
  requester_user_id: string;
  service_key: string;
  urgency: string;
  description: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export function getCustomerOrganizations() {
  return apiFetch<{ organizations: CustomerOrganization[] }>("/api/v1/customer/organizations");
}

export function getCustomerServiceRequests() {
  return apiFetch<{ service_requests: CustomerServiceRequest[] }>("/api/v1/customer/service-requests");
}

export function getCustomerVerification(organizationId: string) {
  return apiFetch<{ organization: Pick<CustomerOrganization, "id"|"verification_status">; verifications: Array<{
    id: string; verification_type: string; status: string; provider: string | null; reference: string | null;
    submitted_at: string | null; verified_at: string | null; expires_at: string | null; created_at: string;
  }> }>(`/api/v1/customer/organizations/${encodeURIComponent(organizationId)}/verification`);
}
