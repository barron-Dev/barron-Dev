"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch } from "../../../../../../lib/api";

type Camera = { id: string; name: string; endpoint_host?: string; protocol?: string; enabled?: boolean; created_at?: string };
type Probe = { id: string; outcome: string; observed_at: string; duration_ms?: number; frame_sha256?: string | null; error_code?: string | null };

export default function CustomerWatchtowerWorkflow() {
  const [cameras, setCameras] = useState<Camera[]>([]);
  const [selected, setSelected] = useState("");
  const [probes, setProbes] = useState<Probe[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const result = await apiFetch<Camera[] | { items?: Camera[] }>("/api/v1/watchtower/cameras");
      const list = Array.isArray(result) ? result : Array.isArray(result.items) ? result.items : [];
      setCameras(list);
      setSelected(current => current && list.some(c => c.id === current) ? current : list[0]?.id || "");
    } catch (e) { setError(e instanceof Error ? e.message : "Camera registry unavailable"); }
    finally { setLoading(false); }
  }, []);

  const loadProbes = useCallback(async (id: string) => {
    if (!id) { setProbes([]); return; }
    try {
      const result = await apiFetch<Probe[] | { items?: Probe[] }>(`/api/v1/watchtower/cameras/${encodeURIComponent(id)}/probes`);
      setProbes(Array.isArray(result) ? result : Array.isArray(result.items) ? result.items : []);
    } catch (e) { setError(e instanceof Error ? e.message : "Probe history unavailable"); setProbes([]); }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { void loadProbes(selected); }, [selected, loadProbes]);

  async function probe() {
    if (!selected || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await apiFetch<Probe>(`/api/v1/watchtower/cameras/${encodeURIComponent(selected)}/probe`, { method: "POST" });
      setNotice(`Probe recorded: ${result.outcome || "outcome returned by service"}`);
      await loadProbes(selected);
    } catch (e) { setError(e instanceof Error ? e.message : "Camera probe failed"); }
    finally { setBusy(false); }
  }

  return <main className="min-h-screen bg-[#050b16] text-slate-100 p-6">
    <div className="mx-auto max-w-5xl space-y-6">
      <nav className="text-sm text-slate-400"><Link href="/customer/services/ai_security" className="underline">AI Security</Link> / Watchtower</nav>
      <header><p className="text-xs uppercase tracking-[.2em] text-cyan-300">Service 09 · AI Security</p><h1 className="mt-2 text-3xl font-semibold">Watchtower workflow</h1><p className="mt-2 max-w-3xl text-slate-300">Tenant-scoped camera registry, real stream probes and recorded probe evidence. A missing source or failed probe is not a clean result.</p></header>
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {[
          ["AI governance & routing", "Governed model/provider routes; runtime status must come from live APIs."],
          ["AI execution & orchestration", "Execution traces and status must be fetched from the governed runtime."],
          ["AI Action Verification", "Separate draft workstream; production verification is not assumed."],
          ["Watchtower", "Live camera registry, probe attempts and probe evidence history."],
          ["Omni-Vision", "Separate media evidence workstream; no detector is implied by this page."],
          ["Attribution & intelligence", "Correlate existing threat, scam, brand and dark-web records."]
        ].map(([title, description]) => <article key={title} className="rounded-xl border border-slate-700 bg-slate-900/60 p-4"><h2 className="font-medium">{title}</h2><p className="mt-2 text-sm text-slate-400">{description}</p></article>)}
      </section>
      <section className="rounded-xl border border-slate-700 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-xl font-semibold">Camera sources</h2><p className="mt-1 text-sm text-slate-400">Loaded from the authenticated API; no sample cameras are inserted.</p></div><button onClick={() => void load()} className="rounded-lg border border-slate-600 px-3 py-2 text-sm">Refresh</button></div>
        {loading ? <p className="py-6 text-slate-400">Loading authenticated camera registry…</p> : error && cameras.length === 0 ? <p role="alert" className="py-6 text-amber-300">{error}</p> : cameras.length === 0 ? <p className="py-6 text-slate-400">No camera records returned by the service. This does not mean coverage is clean.</p> : <div className="mt-4 flex flex-wrap gap-3"><select aria-label="Camera" className="min-w-64 rounded-lg border border-slate-600 bg-slate-950 px-3 py-2" value={selected} onChange={e => setSelected(e.target.value)}>{cameras.map(c => <option key={c.id} value={c.id}>{c.name} · {c.endpoint_host || c.protocol || "configured source"}</option>)}</select><button disabled={!selected || busy} onClick={() => void probe()} className="rounded-lg bg-cyan-300 px-4 py-2 font-semibold text-slate-950 disabled:opacity-50">{busy ? "Probing real stream…" : "Run camera probe"}</button></div>}
        {notice && <p role="status" className="mt-3 text-sm text-emerald-300">{notice}</p>}{error && cameras.length > 0 && <p role="alert" className="mt-3 text-sm text-amber-300">{error}</p>}
      </section>
      <section className="rounded-xl border border-slate-700 p-5"><h2 className="text-xl font-semibold">Probe evidence history</h2><p className="mt-1 text-sm text-slate-400">Records returned by the tenant-scoped API.</p>{!selected ? <p className="py-5 text-slate-400">Select a configured camera to inspect evidence.</p> : probes.length === 0 ? <p className="py-5 text-slate-400">No probe records returned. Source coverage is unverified.</p> : <div className="mt-4 space-y-3">{probes.map(p => <article key={p.id} className="rounded-lg border border-slate-800 p-3"><div className="flex flex-wrap justify-between gap-2"><strong>{p.outcome}</strong><time className="text-sm text-slate-400">{new Date(p.observed_at).toLocaleString()}</time></div>{p.frame_sha256 && <p className="mt-2 break-all font-mono text-xs text-slate-400">Frame SHA-256: {p.frame_sha256}</p>}{p.error_code && <p className="mt-1 text-sm text-amber-300">Error: {p.error_code}</p>}</article>)}</div>}</section>
      <p className="text-xs text-slate-500">This page does not claim a detector, model inference, durable signed journal, or production camera coverage unless the relevant runtime and evidence APIs are separately verified.</p>
    </div>
  </main>;
}
