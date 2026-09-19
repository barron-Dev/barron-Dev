"use client";

import { use, useEffect, useMemo, useState } from "react";

const DEFAULT_API_BASE = "https://cyclothone-api-production.up.railway.app";
const API = (process.env.NEXT_PUBLIC_CYCLOTHONE_API_URL ?? DEFAULT_API_BASE).trim().replace(/\/$/, "");

type ModuleDef = { title: string; section: string; endpoint?: string };
type Row = Record<string, unknown>;

const modules: Record<string, ModuleDef> = {
  detection: { title: "Detection", section: "OPERATIONS", endpoint: "/api/v1/console/threats?limit=50&offset=0&sort=created_at&direction=desc" },
  response: { title: "Response", section: "OPERATIONS", endpoint: "/api/v1/investigations" },
  "intelligence/web": { title: "Web Intel", section: "INTELLIGENCE", endpoint: "/api/v1/web-intel/targets" },
  "intelligence/scam": { title: "Scam", section: "INTELLIGENCE" },
  "intelligence/dark-web": { title: "Dark Web", section: "INTELLIGENCE", endpoint: "/api/v1/darkweb/stats" },
  "intelligence/brand": { title: "Brand", section: "INTELLIGENCE", endpoint: "/api/v1/brand" },
  "convergence/physical": { title: "Physical", section: "CONVERGENCE", endpoint: "/api/v1/physical/stats" },
  "convergence/ai": { title: "AI Security", section: "CONVERGENCE", endpoint: "/api/v1/ai/agents" },
  "assurance/compliance": { title: "Compliance", section: "ASSURANCE", endpoint: "/api/v1/compliance/assurance" },
  "assurance/recovery": { title: "Recovery", section: "ASSURANCE" },
  "assurance/hunting": { title: "Hunting", section: "ASSURANCE", endpoint: "/api/v1/hunts" },
  "platform/federation": { title: "Federation", section: "PLATFORM", endpoint: "/api/v1/federation/peers" },
  "platform/developer": { title: "Developer", section: "PLATFORM" },
  "platform/settings": { title: "Settings", section: "PLATFORM" },
};

function authHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = sessionStorage.getItem("cyclothone_access_token") ?? "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function scalar(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function DataView({ data }: { data: unknown }) {
  if (Array.isArray(data)) {
    const rows = data.filter((x): x is Row => !!x && typeof x === "object" && !Array.isArray(x));
    if (rows.length) {
      const columns = Array.from(new Set(rows.flatMap(row => Object.keys(row)))).slice(0, 8);
      return (
        <div className="overflow-auto border border-[#1a2330]">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-[#111823] text-[9px] uppercase tracking-[.12em] text-[#5a6675]">
              <tr>{columns.map(column => <th key={column} className="border-b border-[#1a2330] px-3 py-2">{column}</th>)}</tr>
            </thead>
            <tbody>
              {rows.slice(0, 100).map((row, index) => (
                <tr key={index} className="border-b border-[#1a2330] last:border-0">
                  {columns.map(column => <td key={column} className="max-w-[320px] truncate px-3 py-2 font-mono text-[#8a97a8]" title={scalar(row[column])}>{scalar(row[column])}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    return <pre className="overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] text-[#8a97a8]">{JSON.stringify(data, null, 2)}</pre>;
  }

  if (data && typeof data === "object") {
    const entries = Object.entries(data as Row);
    return (
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {entries.slice(0, 30).map(([key, value]) => (
          <div key={key} className="border border-[#1a2330] bg-[#0a0e14] p-3">
            <div className="font-mono text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{key}</div>
            <div className="mt-2 break-words font-mono text-[12px] text-[#e8eef6]">{scalar(value)}</div>
          </div>
        ))}
      </div>
    );
  }

  return <div className="border border-[#1a2330] bg-[#0a0e14] p-6 font-mono text-[11px] text-[#8a97a8]">{scalar(data)}</div>;
}

export default function ModulePage({ params }: { params: Promise<{ module?: string[] }> }) {
  const { module: segments = [] } = use(params);
  const [data, setData] = useState<unknown>(null);
  const [status, setStatus] = useState("Loading");
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState("");

  const key = useMemo(() => segments.join("/"), [segments]);
  const module = modules[key];

  useEffect(() => {
    if (!module?.endpoint) {
      setStatus(module ? "Read API not exposed" : "Route not found");
      return;
    }

    let cancelled = false;
    async function load() {
      setStatus("Loading");
      setError(null);
      try {
        const response = await fetch(API + module.endpoint, { headers: authHeaders(), cache: "no-store" });
        const body = await response.text();
        if (!response.ok) {
          if (response.status === 401 || response.status === 403) throw new Error("Authentication required");
          throw new Error(`API ${response.status}`);
        }
        let parsed: unknown = null;
        if (body) {
          try { parsed = JSON.parse(body); }
          catch { throw new Error("Backend returned non-JSON data"); }
        }
        if (!cancelled) { setData(parsed); setStatus("Live API data"); }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to load module");
          setStatus("API error");
        }
      }
    }
    void load();
    return () => { cancelled = true; };
  }, [module?.endpoint]);

  if (!module) return <main className="min-h-screen bg-[#05070a] p-8 text-[#e8eef6]"><a href="/" className="text-[#00d9ff]">← Cyclothone</a><h1 className="mt-8 text-2xl font-semibold">Module not found</h1></main>;

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex h-12 items-center border-b border-[#1a2330] bg-[#0a0e14] px-4">
        <a href="/" className="font-semibold">◈ Cyclothone</a>
        <span className="ml-5 font-mono text-[10px] text-[#5a6675]">{module.section} / {module.title.toUpperCase()}</span>
        <span className={`ml-auto font-mono text-[10px] ${status === "Live API data" ? "text-[#00e07a]" : "text-[#ffb020]"}`}>{status}</span>
      </header>
      <section className="mx-auto max-w-[1400px] p-6">
        <div className="mb-5 flex items-end justify-between border-b border-[#1a2330] pb-5">
          <div>
            <p className="font-mono text-[10px] tracking-[.16em] text-[#5a6675]">{module.section}</p>
            <h1 className="mt-1 text-2xl font-semibold">{module.title}</h1>
            <p className="mt-2 text-sm text-[#8a97a8]">Production control-plane module backed by Cyclothone APIs.</p>
          </div>
        </div>
        {error && <div className="mb-5 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-[12px] text-[#ff6b83]">{error}</div>}
        {status === "Authentication required" && (
          <div className="mb-5 flex gap-2">
            <input type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="Access token" className="border border-[#2a3646] bg-[#0a0e14] px-3 py-2 font-mono text-[11px]" />
            <button onClick={() => { sessionStorage.setItem("cyclothone_access_token", token.trim()); location.reload(); }} className="border border-[#00d9ff] px-4 py-2 text-[11px] text-[#00d9ff]">Connect</button>
          </div>
        )}
        {module.endpoint && !error && data !== null && <DataView data={data} />}
        {!module.endpoint && <div className="border border-[#1a2330] bg-[#0a0e14] p-6 text-sm text-[#8a97a8]"><div className="font-medium text-[#e8eef6]">Control-plane route registered</div><p className="mt-2">No tenant-scoped read endpoint is currently exposed for this module. The console will not invent or synthesize operational state.</p></div>}
      </section>
    </main>
  );
}
