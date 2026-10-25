const MAX_QUERY_LENGTH = 500;
const MAX_RESULTS = 8;

export function normalizeExternalQuery(value) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/\s+/g, " ").slice(0, MAX_QUERY_LENGTH);
}
export function normalizeBraveResults(payload, limit = 5) {
  const rows = Array.isArray(payload?.web?.results) ? payload.web.results : [];
  const count = Math.min(Math.max(Number(limit) || 5, 1), MAX_RESULTS);
  return rows.slice(0, count).flatMap((row) => {
    if (typeof row?.url !== "string") return [];
    let parsed;
    try { parsed = new URL(row.url); } catch { return []; }
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return [];
    return [{ title: String(row.title || "Untitled source").slice(0,300), url: parsed.href,
      snippet: String(row.description || "").slice(0,2000),
      publishedAt: typeof row.page_age === "string" ? row.page_age : null, provider: "brave_search" }];
  });
}
export async function searchExternal({ query, count = 5, country = "ALL", searchLang = "en" } = {}) {
  const normalizedQuery = normalizeExternalQuery(query);
  if (!normalizedQuery) return { available: false, provider: "brave_search", reason: "invalid_query", query: "", results: [] };
  const apiKey = process.env.BRAVE_SEARCH_API_KEY;
  if (!apiKey) return { available: false, provider: "brave_search", reason: "not_configured", query: normalizedQuery, results: [] };
  const url = new URL("https://api.search.brave.com/res/v1/web/search");
  url.searchParams.set("q", normalizedQuery);
  url.searchParams.set("count", String(Math.min(Math.max(Number(count) || 5, 1), MAX_RESULTS)));
  url.searchParams.set("country", /^[A-Z]{2,3}$/.test(country) ? country : "ALL");
  url.searchParams.set("search_lang", /^[a-z]{2,3}$/.test(searchLang) ? searchLang : "en");
  let response;
  try {
    response = await fetch(url, { headers: { Accept: "application/json", "X-Subscription-Token": apiKey }, signal: AbortSignal.timeout(10000) });
  } catch { return { available: false, provider: "brave_search", reason: "provider_unreachable", query: normalizedQuery, results: [] }; }
  if (!response.ok) return { available: false, provider: "brave_search", reason: response.status === 401 || response.status === 403 ? "provider_auth_failed" : "provider_error", query: normalizedQuery, results: [] };
  let payload;
  try { payload = await response.json(); } catch { return { available: false, provider: "brave_search", reason: "invalid_provider_response", query: normalizedQuery, results: [] }; }
  return { available: true, provider: "brave_search", query: normalizedQuery, results: normalizeBraveResults(payload, count) };
}
