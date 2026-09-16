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

const API_BASE = (process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "").replace(/\/$/, "");
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
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers, cache: "no-store" });
  if (!response.ok) {
    const message = response.status === 401 ? "Authentication required" :
      response.status === 403 ? "console:read scope required" : `API ${response.status}`;
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export function getOverview() {
  return apiFetch<ConsoleOverview>("/api/v1/console/overview");
}
