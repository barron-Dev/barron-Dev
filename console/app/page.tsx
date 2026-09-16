"use client";

import { useEffect, useMemo, useState } from "react";

type FeedItem = {
  id: string;
  device_id: string | null;
  detector: string;
  score: number | null;
  verdict: string | null;
  reasons: string[] | null;
  created_at: string;
  mitre_technique: string | null;
};

type Overview = {
  generated_at: string;
  agents: { total: number };
  threats: { last_24h: number; previous_24h: number; delta_percent: number | null };
  critical: { count: number };
  uptime_percent: number | null;
  response_p95_ms: number | null;
  coverage: Record<string, { observed: number } | null>;
  feed: FeedItem[];
};

const apiBase = process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "";

function Icon({ name }: { name: "shield" | "radar" | "bolt" | "globe" | "phone" | "eye" | "fingerprint" | "badge" | "brain" | "scroll" | "rewind" | "search" | "nodes" | "terminal" | "settings" }) {
  const paths: Record<string, string> = {
    shield: "M12 3l7 3v5c0 4.6-3 8.5-7 10-4-1.5-7-5.4-7-10V6l7-3z M9 12l2 2 4-5",
    radar: "M12 12h.01 M4.9 4.9a10 10 0 0114.2 0 M7.8 7.8a6 6 0 018.4 0 M12 12l5-5",
    bolt: "M13 2L4 14h6l-1 8 9-12h-6l1-8z",
    globe: "M12 3a9 9 0 100 18 9 9 0 000-18z M3 12h18 M12 3c2.2 2.4 3.3 5.4 3.3 9S14.2 18.6 12 21c-2.2-2.4-3.3-5.4-3.3-9S9.8 5.4 12 3z",
    phone: "M6 3h4l2 5-3 2a14 14 0 006 6l2-3 5 2v4c0 1-1 2-2 2C11 21 3 13 3 4c0-1 1-1 3-1z M16 8l5-5 M21 8V3h-5",
    eye: "M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6z M4 4l16 16",
    fingerprint: "M12 11a3 3 0 013 3v6 M8 20v-6a4 4 0 018 0v2 M6 18v-4a6 6 0 0112 0 M4 16v-2a8 8 0 0116 0",
    badge: "M12 3l3 2 3-.2.8 3 2.2 2.2-2.2 2.2-.8 3-3-.2-3 2-3-2-3 .2-.8-3L4.8 10 7 7.8l.8-3L11 5l1-2z M9 12l2 2 4-4",
    brain: "M9 4a3 3 0 00-3 3v1a3 3 0 00-2 5 3 3 0 002 5v1a3 3 0 003 3 M15 4a3 3 0 013 3v1a3 3 0 012 5 3 3 0 01-2 5v1a3 3 0 01-3 3 M9 8h6 M9 16h6 M12 4v16",
    scroll: "M7 4h10v16H7a2 2 0 010-4h10 M7 4a2 2 0 000 4h10 M10 12h4 M10 15h3",
    rewind: "M9 7H4l5-5 M4 7a8 8 0 111.5 9 M9 12h7 M13 9l3 3-3 3",
    search: "M10.5 4a6.5 6.5 0 104.6 11.1L20 20 M10.5 7v7 M7 10.5h7",
    nodes: "M6 6h.01 M18 6h.01 M12 18h.01 M6 6l6 12 6-12 M6 6h12",
    terminal: "M4 5h16v14H4z M7 9l3 3-3 3 M12 15h4",
    settings: "M12 8a4 4 0 100 8 4 4 0 000-8z M4 12h2m12 0h2M12 4v2m0 12v2M6.3 6.3l1.4 1.4m8.6 8.6l1.4 1.4m0-11.4l-1.4 1.4m-8.6 8.6l-1.4 1.4",
  };
  return <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4"><path d={paths[name]} /></svg>;
}

const nav = [
  ["OPERATIONS", [["Overview", "shield"], ["Threats", "radar"], ["Detection", "radar"], ["Response", "bolt"]]],
  ["INTELLIGENCE", [["Web Intel", "globe"], ["Scam", "phone"], ["Dark Web", "eye"], ["Brand", "fingerprint"]]],
  ["CONVERGENCE", [["Physical", "badge"], ["AI Security", "brain"]]],
  ["ASSURANCE", [["Compliance", "scroll"], ["Recovery", "rewind"], ["Hunting", "search"]]],
  ["PLATFORM", [["Federation", "nodes"], ["Developer", "terminal"], ["Settings", "settings"]]],
] as const;

function Stat({ label, value, meta, bad }: { label: string; value: string; meta?: string; bad?: boolean }) {
  return <div className="border-r border-[#1a2330] px-5 last:border-r-0">
    <div className={"font-mono text-[32px] font-bold leading-none " + (bad ? "bg-gradient-to-br from-[#ff2d55] to-[#ff7a1a] bg-clip-text text-transparent" : "text-[#e8eef6]")}>{value}</div>
    <div className="mt-2 text-[11px] font-medium uppercase tracking-[.12em] text-[#5a6675]">{label}</div>
    {meta && <div className="mt-1 font-mono text-[11px] text-[#8a97a8]">{meta}</div>}
  </div>;
}

function Coverage({ label, value }: { label: string; value: number | null }) {
  const shown = value == null ? "—" : value.toLocaleString();
  const width = value == null ? 0 : Math.min(100, Math.max(0, value));
  return <div className="grid grid-cols-[140px_1fr_72px] items-center gap-3 py-1.5">
    <div className="text-[12px] text-[#8a97a8]">{label}</div>
    <div className="h-1 overflow-hidden rounded-full bg-[#030508]"><div className="h-full bg-[#4a9eff] transition-all duration-200" style={{ width: `${width}%` }} /></div>
    <div className="text-right font-mono text-[11px] text-[#8a97a8]">{shown}</div>
  </div>;
}

export default function Home() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [sidebar, setSidebar] = useState(true);
  const [searchOpen, setSearchOpen] = useState(false);

  const load = async () => {
    try {
      const stored = token || (typeof window !== "undefined" ? sessionStorage.getItem("sentinel_access_token") ?? "" : "");
      const headers: HeadersInit = stored ? { Authorization: `Bearer ${stored}` } : {};
      const res = await fetch(`${apiBase}/api/v1/console/overview`, { headers, cache: "no-store" });
      if (!res.ok) throw new Error(res.status === 401 ? "Authentication required" : res.status === 403 ? "console:read scope required" : `API ${res.status}`);
      setData(await res.json()); setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to reach Sentinel API"); }
  };

  useEffect(() => { load(); }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setSearchOpen(true); }
      if ((e.metaKey || e.ctrlKey) && e.key === "\\") { e.preventDefault(); setSidebar(v => !v); }
      if (e.key === "Escape") setSearchOpen(false);
    };
    window.addEventListener("keydown", onKey); return () => window.removeEventListener("keydown", onKey);
  }, []);

  const threatDelta = useMemo(() => data?.threats.delta_percent == null ? "—" : `${data.threats.delta_percent > 0 ? "+" : ""}${data.threats.delta_percent}%`, [data]);

  return <main className="flex h-screen min-w-[1100px] flex-col overflow-hidden bg-[#05070a] text-[#e8eef6]">
    <header className="flex h-12 shrink-0 items-center border-b border-[#1a2330] bg-[#0a0e14] px-4">
      <div className="flex w-[240px] shrink-0 items-center gap-2">
        <div className="text-[#e8eef6]"><Icon name="shield" /></div><span className="font-semibold tracking-tight">Sentinel</span>
        <span className="ml-2 rounded border border-[#00d9ff] px-1.5 py-0.5 font-mono text-[10px] text-[#00d9ff]">ae-1</span>
      </div>
      <button onClick={() => setSearchOpen(true)} className="mx-auto flex h-7 w-[440px] items-center gap-2 rounded border border-[#2a3646] bg-[#030508] px-3 text-left text-[12px] text-[#5a6675] hover:border-[#3a4a5e]" aria-label="Open command palette">
        <Icon name="search" /><span>Search detections, devices, cases, IOCs…</span><kbd className="ml-auto rounded border border-[#2a3646] px-1.5 py-0.5 font-mono text-[10px] text-[#8a97a8]">⌘K</kbd>
      </button>
      <div className="ml-auto flex w-[240px] items-center justify-end gap-4 text-[#8a97a8]"><span className="relative">◉<b className="absolute -right-2 -top-1 rounded-full bg-[#ff2d55] px-1 text-[8px] text-white">3</b></span><span className="font-mono text-[11px]">OPS</span><span className="h-6 w-6 rounded-full border border-[#2a3646] bg-[#111823] text-center text-[10px] leading-6">B</span></div>
    </header>

    <div className="flex min-h-0 flex-1">
      <aside className={(sidebar ? "w-[240px] " : "w-[56px] ") + "shrink-0 overflow-hidden border-r border-[#1a2330] bg-[#0a0e14] transition-[width] duration-150"}>
        <nav className="px-2 py-3">{nav.map(([group, items]) => <div key={group} className="mb-4"><div className={(sidebar ? "px-2 " : "px-0 text-center ") + "mb-1 text-[9px] font-semibold tracking-[.16em] text-[#5a6675]"}>{sidebar ? group : "·"}</div>{items.map(([label, icon]) => <button key={label} className={(label === "Overview" ? "border-l-2 border-[#00d9ff] bg-[#111823] text-[#00d9ff] " : "border-l-2 border-transparent text-[#8a97a8] ") + "mb-0.5 flex h-8 w-full items-center gap-3 rounded-r px-3 text-[12px] hover:bg-[#111823]"} title={label}><Icon name={icon as Parameters<typeof Icon>[0]["name"]} />{sidebar && <span>{label}</span>}</button>)}</div>)}</nav>
      </aside>

      <section className="min-w-0 flex-1 overflow-auto">
        <div className="border-b border-[#1a2330] px-6 py-4"><div className="flex items-center justify-between"><div><div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Operational posture</div><h1 className="mt-1 text-xl font-semibold tracking-tight">Executive Overview</h1></div><div className="flex gap-1 rounded border border-[#1a2330] bg-[#030508] p-0.5">{["24h","7d","30d","custom"].map((x,i)=><button key={x} className={(i===0 ? "bg-[#111823] text-[#e8eef6] " : "text-[#5a6675] ")+"rounded px-2.5 py-1 text-[11px] hover:text-[#e8eef6]"}>{x}</button>)}</div></div></div>

        <div className="grid grid-cols-4 border-b border-[#1a2330] py-6">
          <Stat label="Agents" value={data ? data.agents.total.toLocaleString() : "—"} meta="registered devices" />
          <Stat label="Threats" value={data ? data.threats.last_24h.toLocaleString() : "—"} meta={threatDelta + " vs prior 24h"} bad={!!data?.threats.delta_percent && data.threats.delta_percent > 0} />
          <Stat label="Critical cases" value={data ? data.critical.count.toLocaleString() : "—"} meta="created in 24h" bad={!!data?.critical.count} />
          <Stat label="API uptime" value={data?.uptime_percent == null ? "—" : `${data.uptime_percent}%`} meta="telemetry not configured" />
        </div>

        {error && <div className="mx-6 mt-5 flex items-center justify-between border border-[#ff2d55]/40 bg-[#ff2d55]/5 px-4 py-3 text-[12px]"><div><span className="mr-2 text-[#ff2d55]">◆</span>{error}</div><div className="flex gap-2"><input value={token} onChange={e=>setToken(e.target.value)} placeholder="Bearer token" type="password" className="w-64 border border-[#2a3646] bg-[#030508] px-2 py-1 font-mono text-[11px] outline-none focus:border-[#00d9ff]"/><button onClick={()=>{sessionStorage.setItem("sentinel_access_token",token);load();}} className="border border-[#00d9ff] px-3 py-1 text-[11px] text-[#00d9ff]">Connect</button></div></div>}

        <div className="grid grid-cols-2 gap-4 p-6">
          <div className="border border-[#1a2330] bg-[#0a0e14] p-4"><div className="mb-3 flex items-center justify-between"><span className="text-[12px] font-medium">Detection volume</span><span className="font-mono text-[10px] text-[#5a6675]">24h</span></div><div className="flex h-12 items-end gap-1">{[20,34,27,50,42,70,55,80,62,90,68,44,58,76,49,66,82,61,72,52,88,63,77,48,57,71,53,69,81,60].map((h,i)=><div key={i} className="flex-1 bg-[#00d9ff]/50" style={{height:`${h}%`}} />)}</div></div>
          <div className="border border-[#1a2330] bg-[#0a0e14] p-4"><div className="mb-3 flex items-center justify-between"><span className="text-[12px] font-medium">Response time · p95</span><span className="font-mono text-[10px] text-[#00d9ff]">{data?.response_p95_ms == null ? "—" : `${data.response_p95_ms}ms`}</span></div><div className="flex h-12 items-center gap-1">{[22,28,35,26,32,29,38,31,25,27,23,20,24,18,22,19,21,17,20,16,18,15,17,14,16,13,15,12,14,11].map((h,i)=><div key={i} className="flex-1 bg-[#00d9ff]/40" style={{height:`${h}%`}} />)}</div></div>
        </div>

        <div className="grid grid-cols-[1.2fr_.8fr] gap-4 px-6 pb-6">
          <div className="border border-[#1a2330] bg-[#0a0e14] p-4"><div className="mb-3 text-[12px] font-medium">Coverage across layers</div><Coverage label="Endpoints" value={data ? 100 : null}/><Coverage label="Web · surface" value={data?.coverage.web_surface ? data.coverage.web_surface.observed : null}/><Coverage label="Deep web" value={data?.coverage.deep_web ? data.coverage.deep_web.observed : null}/><Coverage label="Dark web" value={data?.coverage.dark_web ? data.coverage.dark_web.observed : null}/><Coverage label="Physical" value={data?.coverage.physical ? data.coverage.physical.observed : null}/><Coverage label="AI agents" value={data?.coverage.ai_agents ? data.coverage.ai_agents.observed : null}/></div>
          <div className="border border-[#1a2330] bg-[#0a0e14] p-4"><div className="mb-3 flex items-center justify-between"><span className="text-[12px] font-medium">Live threat feed</span><span className="flex items-center gap-1 font-mono text-[10px] text-[#00e07a]"><i className="live-dot h-1.5 w-1.5 rounded-full bg-[#00e07a]"/>LIVE</span></div><div className="divide-y divide-[#1a2330]">{data?.feed?.length ? data.feed.map(item => <div key={item.id} className="feed-row grid grid-cols-[64px_1fr_46px] gap-2 py-2 text-[11px]"><span className="font-semibold uppercase text-[#ff7a1a]">{item.verdict ?? "—"}</span><span className="min-w-0 truncate text-[#8a97a8]">{item.reasons?.[0] ?? item.detector}{item.device_id ? ` · ${item.device_id.slice(0,8)}` : ""}</span><span className="font-mono text-right text-[#5a6675]">{new Date(item.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}</span></div>) : <div className="py-10 text-center text-[12px] text-[#5a6675]">No detections returned by the API.</div>}</div></div>
        </div>
      </section>
    </div>

    <footer className="flex h-6 shrink-0 items-center justify-between border-t border-[#1a2330] bg-[#0a0e14] px-3 font-mono text-[10px] text-[#5a6675]"><span><i className="live-dot mr-1 inline-block h-1.5 w-1.5 rounded-full bg-[#00e07a]"/>live · agents {data?.agents.total ?? "—"}</span><span>region: ae-1 · api lag: —</span><span>{data ? new Date(data.generated_at).toISOString().slice(11,19)+"Z" : "—"}</span></footer>

    {searchOpen && <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" onClick={()=>setSearchOpen(false)}><div className="mx-auto mt-24 w-[600px] border border-[#2a3646] bg-[#0a0e14] shadow-2xl" onClick={e=>e.stopPropagation()}><div className="flex items-center gap-2 border-b border-[#1a2330] p-4"><Icon name="search"/><input autoFocus placeholder="> Search Sentinel" className="w-full bg-transparent text-sm outline-none placeholder:text-[#5a6675]" /></div><div className="p-3"><div className="mb-2 px-2 text-[9px] font-semibold tracking-[.16em] text-[#5a6675]">SUGGESTED</div>{[["Show critical detections","radar"],["Executive summary","shield"],["Open response queue","bolt"]].map(([label,icon])=><button key={label} className="flex w-full items-center gap-3 rounded px-2 py-2 text-left text-[12px] hover:bg-[#111823]"><Icon name={icon as Parameters<typeof Icon>[0]["name"]}/>{label}<span className="ml-auto font-mono text-[10px] text-[#5a6675]">↵</span></button>)}</div></div></div>}
  </main>;
}
