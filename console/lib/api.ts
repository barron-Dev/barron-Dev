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

export function setApiToken(token: string) {
  accessToken = token.trim() || null;
}

export function clearApiToken() {
  accessToken = null;
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
  if (!response.ok) {
    const message =
      response.status === 401 ? "Authentication required" :
      response.status === 403 ? "console:read scope required" :
      `Backend request failed (HTTP ${response.status})`;
    throw new Error(message);
  }

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("Backend returned a non-JSON response");
  }

  try {
    return await response.json() as T;
  } catch {
    throw new Error("Backend returned invalid JSON");
  }
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
