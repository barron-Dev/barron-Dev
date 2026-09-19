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
