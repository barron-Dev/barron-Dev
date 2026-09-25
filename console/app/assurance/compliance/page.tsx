"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch, setApiToken } from "../../../lib/api";

type Framework = { id?: string; key?: string; name?: string; version?: string; description?: string };
type Control = { id?: string; stable_id?: string; control_code?: string; title?: string; name?: string; description?: string; framework?: string };
type Pack = { id: string; framework_id: string; period_start: string; period_end: string; status: string; overall_score: number | null; controls_passing: number | null; controls_total: number | null; evidence_count: number | null; verification_status: string | null; created_at: string; pack_sha256?: string | null };

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [controls, setControls] = useState<Control[]>([]);
  const [packs, setPacks] = useState<Pack[]>([]);
  const [framework, setFramework] = useState("");
  const [loading, setLoading] = useState(true);
  const [controlsLoading, setControlsLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  const now = useMemo(() => new Date(), []);
  const end = now.toISOString();
  const start = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();

  useEffect(() => {
    setApiToken(sessionStorage.getItem("cyclothone_access_token") || "");
    void load();
  }, []);

  async function load() {
    setLoading(true); setError("");
    try {
      const f = await apiFetch<Framework[]>("/api/v1/compliance/frameworks");
      setFrameworks(f);
      const first = f[0];
      const key = String(first?.key ?? first?.id ?? "");
      setFramework(key);
      if (key) await loadControls(key);
      const p = await apiFetch<Pack[]>("/api/v1/compliance/packs");
      setPacks(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load compliance service");
    } finally { setLoading(false); }
  }

  async function loadControls(key: string) {
    setControlsLoading(true);
    try {
      setControls(await apiFetch<Control[]>(`/api/v1/compliance/controls?framework=${encodeURIComponent(key)}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load controls");
      setControls([]);
    } finally { setControlsLoading(false); }
  }

  async function selectFramework(value: string) {
    setFramework(value); setResult(null); setError("");
    if (value) await loadControls(value);
  }

  async function runAssessment() {
    if (!framework) return;
    setBusy(true); setError(""); setResult(null);
    try {
      const r = await apiFetch<Record<string, unknown>>("/api/v1/compliance/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ framework, period_start: start, period_end: end }),
      });
      setResult(r);
      const p = await apiFetch<Pack[]>(`/api/v1/compliance/packs?framework=${encodeURIComponent(framework)}`);
      setPacks(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Compliance assessment failed");
    } finally { setBusy(false); }
  }

  async function verifyPack(id: string) {
    setBusy(true); setError(""); setResult(null);
    try {
      setResult(await apiFetch<Record<string, unknown>>(`/api/v1/compliance/packs/${encodeURIComponent(id)}/verify`, { method: "POST" }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification failed");
    } finally { setBusy(false); }
  }

  if (loading) return <main className="min-h-screen bg-[#05070a] p-8 text-xs text-[#728093]">Loading compliance service…</main>;

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="border-b border-[#1a2330] bg-[#0a0e14] px-5 py-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div><a href="/kontrol" className="text-xs text-[#00d9ff]">← Kontrol</a><h1 className="mt-2 text-2xl font-semibold">Compliance & Assurance</h1><p className="mt-1 text-xs text-[#728093]">Live framework, control, assessment and evidence-pack state.</p></div>
          <button onClick={() => void load()} className="border border-[#2a3646] px-3 py-2 text-[10px]">Refresh</button>
        </div>
      </header>

      <section className="mx-auto max-w-7xl space-y-5 p-5 md:p-8">
        {error && <div className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-xs text-[#ff6b83]">{error}</div>}
        <div className="grid gap-5 lg:grid-cols-[1fr_1.5fr]">
          <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Assessment</div>
            <h2 className="mt-2 text-lg font-medium">Run against real tenant evidence</h2>
            <p className="mt-2 text-xs leading-5 text-[#728093]">The backend performs the assessment. This interface does not create or display synthetic compliance results.</p>
            <select value={framework} onChange={e => void selectFramework(e.target.value)} className="mt-5 w-full border border-[#2a3646] bg-[#05070a] px-3 py-2 text-xs">
              <option value="">Select framework</option>
              {frameworks.map((f, i) => { const key=String(f.key ?? f.id ?? ""); return <option key={key || i} value={key}>{String(f.name ?? key)}{f.version ? ` · ${f.version}` : ""}</option>; })}
            </select>
            <button disabled={!framework || busy} onClick={() => void runAssessment()} className="mt-3 w-full border border-[#00d9ff] px-4 py-3 text-[10px] text-[#00d9ff] disabled:opacity-40">{busy ? "Running…" : "Run assessment"}</button>
            {result && <pre className="mt-4 max-h-72 overflow-auto border border-[#1a2330] bg-[#05070a] p-3 text-[9px] text-[#9aa7b7]">{JSON.stringify(result, null, 2)}</pre>}
          </section>

          <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="flex items-center justify-between"><div><div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Controls</div><h2 className="mt-2 text-lg font-medium">{controls.length} controls in scope</h2></div>{controlsLoading && <span className="text-[9px] text-[#728093]">Loading…</span>}</div>
            {!controls.length ? <div className="mt-6 text-xs text-[#728093]">No controls returned by the authorized API.</div> :
              <div className="mt-4 max-h-[430px] overflow-auto divide-y divide-[#1a2330]">{controls.map((c,i)=><div key={String(c.id ?? c.stable_id ?? i)} className="py-3"><div className="font-mono text-[10px] text-[#00d9ff]">{c.control_code ?? c.stable_id ?? "Control"}</div><div className="mt-1 text-xs">{c.title ?? c.name ?? "Untitled control"}</div>{c.description && <div className="mt-1 text-[10px] leading-4 text-[#728093]">{c.description}</div>}</div>)}</div>}
          </section>
        </div>

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <div className="flex items-center justify-between"><div><div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Evidence packs</div><h2 className="mt-2 text-lg font-medium">Verified assessment artifacts</h2></div><span className="font-mono text-[9px] text-[#728093]">{packs.length} returned</span></div>
          {!packs.length ? <div className="mt-6 border border-dashed border-[#2a3646] p-6 text-xs text-[#728093]">No evidence packs have been produced for this tenant yet.</div> :
            <div className="mt-4 overflow-auto"><table className="w-full text-left text-[10px]"><thead className="text-[9px] uppercase text-[#5a6675]"><tr><th className="py-2 pr-4">Framework</th><th className="py-2 pr-4">Period</th><th className="py-2 pr-4">Score</th><th className="py-2 pr-4">Evidence</th><th className="py-2 pr-4">Verification</th><th/></tr></thead><tbody>{packs.map(p=><tr key={p.id} className="border-t border-[#1a2330]"><td className="py-3 pr-4 font-mono">{p.framework_id}</td><td className="py-3 pr-4">{new Date(p.period_start).toLocaleDateString()} – {new Date(p.period_end).toLocaleDateString()}</td><td className="py-3 pr-4">{p.overall_score ?? "—"}</td><td className="py-3 pr-4">{p.evidence_count ?? "—"}</td><td className="py-3 pr-4">{p.verification_status ?? p.status ?? "—"}</td><td className="py-3 text-right"><button disabled={busy} onClick={() => void verifyPack(p.id)} className="border border-[#2a3646] px-3 py-1.5 text-[9px]">Verify</button></td></tr>)}</tbody></table></div>}
        </section>
      </section>
    </main>
  );
}
