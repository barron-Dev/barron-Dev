"use client";

import { useEffect, useMemo, useState } from "react";

type Detection = {
  id: string;
  tenant_id: string;
  device_id: string;
  event_id: string | null;
  detector: string;
  score: number;
  verdict: string;
  reasons: string[];
  evidence: Record<string, unknown>;
  mitre_technique: string | null;
  created_at: string;
  processed_by_playbooks: boolean;
  processed_by_autocase: boolean;
};

type Result = { items: Detection[]; total: number; limit: number; offset: number };

const API = process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "";
const headers = (token: string) => token ? { Authorization: `Bearer ${token}` } : {};

function Icon({ kind }: { kind: "shield" | "search" | "close" | "chevron" }) {
  const paths = {
    shield: "M12 3l7 3v5c0 4.6-3 8.5-7 10-4-1.5-7-5.4-7-10V6l7-3z M9 12l2 2 4-5",
    search: "M10.5 4a6.5 6.5 0 104.6 11.1L20 20 M10.5 7v7 M7 10.5h7",
    close: "M6 6l12 12M18 6L6 18",
    chevron: "M9 18l6-6-6-6",
  };
  return <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4"><path d={paths[kind]} /></svg>;
}

function tone(value: string) {
  const v = value.toLowerCase();
  if (v === "block" || v === "critical") return "border-[#ff2d55]/40 bg-[#ff2d55]/10 text-[#ff2d55]";
  if (v === "quarantine" || v === "high") return "border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffb020]";
  if (v === "monitor" || v === "medium") return "border-[#4a9eff]/40 bg-[#4a9eff]/10 text-[#4a9eff]";
  return "border-[#2a3646] bg-[#111823] text-[#8a97a8]";
}

export default function ThreatsPage() {
  const [token, setToken] = useState("");
  const [items, setItems] = useState<Detection[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<Detection | null>(null);
  const [q, setQ] = useState("");
  const [detector, setDetector] = useState("");
  const [verdict, setVerdict] = useState("");
  const [minScore, setMinScore] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const limit = 50;

  const load = async (nextOffset = offset) => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(nextOffset), sort: "created_at", order: "desc" });
      if (detector) params.set("detector", detector);
      if (verdict) params.set("verdict", verdict);
      if (minScore) params.set("min_score", minScore);
      const response = await fetch(`${API}/api/v1/console/threats?${params}`, { headers: headers(token), cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 401 ? "Authentication required" : response.status === 403 ? "console:read scope required" : `API ${response.status}`);
      const body = (await response.json()) as Result;
      setItems(body.items);
      setTotal(body.total);
      setOffset(body.offset);
      setSelected(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to reach Sentinel API");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(0); }, []);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); document.getElementById("threat-search")?.focus(); }
      if (event.key === "Escape") setSelected(null);
      if (event.key === "ArrowDown" && items.length) { event.preventDefault(); const i = selected ? items.findIndex(x => x.id === selected.id) : -1; setSelected(items[Math.min(i + 1, items.length - 1)]); }
      if (event.key === "ArrowUp" && items.length) { event.preventDefault(); const i = selected ? items.findIndex(x => x.id === selected.id) : items.length; setSelected(items[Math.max(i - 1, 0)]); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [items, selected]);

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    return items.filter(x => [x.id, x.device_id, x.event_id, x.detector, x.verdict, x.mitre_technique, ...x.reasons].some(v => (v ?? "").toString().toLowerCase().includes(needle)));
  }, [items, q]);

  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
    <header className="sticky top-0 z-10 flex h-12 items-center border-b border-[#1a2330] bg-[#0a0e14] px-4">
      <a href="/" className="flex items-center gap-2 font-semibold"><Icon kind="shield" /> Sentinel</a>
      <span className="ml-5 font-mono text-[10px] text-[#5a6675]">OPERATIONS / THREATS</span>
      <div className="ml-auto font-mono text-[10px] text-[#5a6675]">⌘K search · ↑↓ select · Esc close</div>
    </header>

    <section className="p-5">
      <div className="mb-4 flex items-end justify-between gap-4">
        <div><div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Detection control plane</div><h1 className="mt-1 text-2xl font-semibold">Threats / Detections</h1></div>
        <div className="font-mono text-[11px] text-[#8a97a8]">{total.toLocaleString()} total</div>
      </div>

      <div className="mb-4 grid grid-cols-[minmax(260px,1fr)_180px_150px_120px_auto] gap-2">
        <label className="relative"><span className="sr-only">Search detections</span><span className="pointer-events-none absolute left-3 top-2.5 text-[#5a6675]"><Icon kind="search" /></span><input id="threat-search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search IDs, devices, detectors, MITRE…" className="h-9 w-full border border-[#2a3646] bg-[#0a0e14] pl-9 pr-3 font-mono text-[11px] outline-none focus:border-[#00d9ff]" /></label>
        <input value={detector} onChange={e => setDetector(e.target.value)} placeholder="Detector" className="h-9 border border-[#2a3646] bg-[#0a0e14] px-3 font-mono text-[11px] outline-none focus:border-[#00d9ff]" />
        <select value={verdict} onChange={e => setVerdict(e.target.value)} className="h-9 border border-[#2a3646] bg-[#0a0e14] px-3 font-mono text-[11px] outline-none focus:border-[#00d9ff]"><option value="">All verdicts</option><option value="block">block</option><option value="quarantine">quarantine</option><option value="monitor">monitor</option><option value="allow">allow</option></select>
        <input value={minScore} onChange={e => setMinScore(e.target.value)} inputMode="decimal" placeholder="Min score" className="h-9 border border-[#2a3646] bg-[#0a0e14] px-3 font-mono text-[11px] outline-none focus:border-[#00d9ff]" />
        <button onClick={() => void load(0)} className="h-9 border border-[#00d9ff] px-4 text-[11px] text-[#00d9ff] hover:bg-[#00d9ff]/10">Apply</button>
      </div>

      {error && <div role="alert" className="mb-4 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-[12px] text-[#ff2d55]">{error}<div className="mt-2 flex gap-2"><input type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="Access token (memory only)" className="w-80 border border-[#2a3646] bg-[#030508] px-2 py-1.5 font-mono text-[11px] text-[#e8eef6]" /><button onClick={() => void load(0)} className="border border-[#ff2d55]/50 px-3 py-1.5 text-[11px]">Retry</button></div></div>}

      <div className="overflow-hidden border border-[#1a2330] bg-[#0a0e14]">
        <div className="grid grid-cols-[24px_190px_140px_100px_110px_1fr_150px] border-b border-[#1a2330] bg-[#111823] px-3 py-2 text-[9px] uppercase tracking-[.12em] text-[#5a6675]"><span /><span>Detection</span><span>Device</span><span>Score</span><span>Verdict</span><span>Detector / MITRE</span><span>Created</span></div>
        {loading && <div className="p-8 text-center font-mono text-[11px] text-[#5a6675]">Loading detections…</div>}
        {!loading && visible.length === 0 && <div className="p-10 text-center"><div className="font-mono text-[12px] text-[#8a97a8]">No detections returned</div><div className="mt-1 text-[11px] text-[#5a6675]">The console does not fabricate rows when the tenant has no matching data.</div></div>}
        {!loading && visible.map(item => <button key={item.id} onClick={() => setSelected(item)} className={(selected?.id === item.id ? "bg-[#111823] border-l-[#00d9ff] " : "border-l-transparent ") + "grid w-full grid-cols-[24px_190px_140px_100px_110px_1fr_150px] border-b border-l-2 border-[#1a2330] px-3 py-3 text-left text-[11px] hover:bg-[#111823]"}>
          <span className="text-[#5a6675]"><Icon kind="chevron" /></span><span className="truncate font-mono text-[#e8eef6]" title={item.id}>{item.id}</span><span className="truncate font-mono text-[#8a97a8]" title={item.device_id}>{item.device_id}</span><span className="font-mono text-[#e8eef6]">{item.score.toFixed(3)}</span><span><span className={`inline-flex rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${tone(item.verdict)}`}>{item.verdict}</span></span><span className="min-w-0"><span className="block truncate text-[#e8eef6]">{item.detector}</span><span className="font-mono text-[9px] text-[#5a6675]">{item.mitre_technique ?? "MITRE —"}</span></span><span className="font-mono text-[10px] text-[#8a97a8]">{new Date(item.created_at).toISOString()}</span>
        </button>)}
      </div>

      <div className="mt-3 flex items-center justify-between font-mono text-[10px] text-[#5a6675]"><span>Showing {total ? offset + 1 : 0}–{Math.min(offset + limit, total)} of {total}</span><div className="flex gap-2"><button disabled={offset === 0 || loading} onClick={() => void load(Math.max(0, offset - limit))} className="border border-[#2a3646] px-3 py-1.5 disabled:opacity-30">Prev</button><button disabled={offset + limit >= total || loading} onClick={() => void load(offset + limit)} className="border border-[#2a3646] px-3 py-1.5 disabled:opacity-30">Next</button></div></div>
    </section>

    {selected && <aside aria-label="Detection detail" className="fixed inset-y-0 right-0 z-20 w-[460px] overflow-auto border-l border-[#2a3646] bg-[#0a0e14] shadow-2xl">
      <div className="sticky top-0 flex items-center justify-between border-b border-[#1a2330] bg-[#0a0e14] px-4 py-3"><div><div className="text-[10px] uppercase tracking-[.14em] text-[#5a6675]">Detection detail</div><div className="mt-1 font-mono text-[11px] text-[#e8eef6]">{selected.id}</div></div><button onClick={() => setSelected(null)} aria-label="Close detail"><Icon kind="close" /></button></div>
      <div className="space-y-5 p-4 text-[11px]">
        <div className="grid grid-cols-2 gap-2"><div className="border border-[#1a2330] p-3"><div className="text-[#5a6675]">Score</div><div className="mt-1 font-mono text-xl">{selected.score.toFixed(3)}</div></div><div className="border border-[#1a2330] p-3"><div className="text-[#5a6675]">Verdict</div><div className="mt-2"><span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${tone(selected.verdict)}`}>{selected.verdict}</span></div></div></div>
        <dl className="space-y-3"><div><dt className="text-[#5a6675]">Detector</dt><dd className="mt-1 font-mono">{selected.detector}</dd></div><div><dt className="text-[#5a6675]">Device</dt><dd className="mt-1 break-all font-mono">{selected.device_id}</dd></div><div><dt className="text-[#5a6675]">Event</dt><dd className="mt-1 break-all font-mono">{selected.event_id ?? "—"}</dd></div><div><dt className="text-[#5a6675]">MITRE technique</dt><dd className="mt-1 font-mono">{selected.mitre_technique ?? "—"}</dd></div><div><dt className="text-[#5a6675]">Created</dt><dd className="mt-1 font-mono">{new Date(selected.created_at).toISOString()}</dd></div><div><dt className="text-[#5a6675]">Pipeline</dt><dd className="mt-1 font-mono">AutoCase: {selected.processed_by_autocase ? "processed" : "pending"} · Playbooks: {selected.processed_by_playbooks ? "processed" : "pending"}</dd></div></dl>
        <div><h2 className="mb-2 text-[10px] uppercase tracking-[.14em] text-[#5a6675]">Reasons</h2>{selected.reasons.length ? <ul className="space-y-1">{selected.reasons.map((reason, i) => <li key={`${selected.id}-reason-${i}`} className="border-l border-[#2a3646] pl-3 text-[#8a97a8]">{reason}</li>)}</ul> : <div className="text-[#5a6675]">No reasons recorded.</div>}</div>
        <div><h2 className="mb-2 text-[10px] uppercase tracking-[.14em] text-[#5a6675]">Evidence</h2><pre className="max-h-80 overflow-auto border border-[#1a2330] bg-[#030508] p-3 font-mono text-[10px] leading-5 text-[#8a97a8]">{JSON.stringify(selected.evidence, null, 2)}</pre></div>
      </div>
    </aside>}
  </main>;
}
