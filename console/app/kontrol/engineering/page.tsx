"use client";

import { useState } from "react";

type Check = { provider: string; status: "ok" | "unknown" | "blocked"; checkedAt: string; source: string; summary: string; details?: any };
type Snapshot = { generatedAt: string; mode: string; results: Check[] };
const style: Record<Check["status"], string> = {
  ok: "border-emerald-400/30 text-emerald-300 bg-emerald-400/5",
  unknown: "border-slate-500/40 text-slate-300 bg-slate-500/5",
  blocked: "border-rose-400/30 text-rose-300 bg-rose-400/5",
};

export default function EngineeringConsole() {
  const [token, setToken] = useState("");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function refresh() {
    if (!token.trim() || busy) return;
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/kontrol/state", { headers: { "x-kontrol-console-token": token.trim() }, cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "State query failed: " + response.status);
      setSnapshot(data as Snapshot);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not retrieve provider state");
      setSnapshot(null);
    } finally { setBusy(false); }
  }
  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1a2330] bg-[#0a0e14] px-5 py-4">
      <div><div className="font-semibold">Cyclothone <span className="ml-2 font-mono text-[10px] text-[#00d9ff]">/kontrol/engineering</span></div><p className="mt-1 text-xs text-[#8a97a8]">Live engineering state · read-only</p></div>
      <a className="text-xs text-[#00d9ff] hover:underline" href="/kontrol">← Control plane</a>
    </header>
    <div className="mx-auto max-w-6xl p-5 md:p-8">
      <section className="border border-[#1a2330] bg-[#0a0e14] p-4 md:p-5">
        <div className="font-mono text-[10px] uppercase tracking-[.16em] text-[#00d9ff]">Verified state query</div>
        <h1 className="mt-2 text-2xl font-semibold">Engineering console</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-[#8a97a8]">Each refresh requests current provider data. Missing credentials and failed checks remain unknown. Railway is deliberately marked blocked until the trial upgrade; no Railway calls are made before then.</p>
        <form className="mt-5 flex flex-col gap-2 sm:flex-row" onSubmit={e => { e.preventDefault(); void refresh(); }}>
          <label className="sr-only" htmlFor="kontrol-read-token">Kontrol read token</label>
          <input id="kontrol-read-token" type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} placeholder="Kontrol read token (not stored)" className="min-w-0 flex-1 border border-[#2a3646] bg-[#030508] px-3 py-2 text-sm outline-none focus:border-[#00d9ff]" />
          <button disabled={!token.trim() || busy} className="border border-[#00d9ff]/50 bg-[#00d9ff]/10 px-5 py-2 text-sm text-[#8cecff] disabled:opacity-40">{busy ? "Querying providers…" : "Refresh live state"}</button>
        </form>
        {error && <div role="alert" className="mt-4 border border-rose-400/30 bg-rose-400/5 p-3 text-sm text-rose-200">{error}</div>}
      </section>
      {snapshot && <>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-xs text-[#8a97a8]"><span>Snapshot: {new Date(snapshot.generatedAt).toLocaleString()}</span><span className="font-mono uppercase tracking-wider">{snapshot.mode}</span></div>
        <section className="mt-4 grid gap-3 md:grid-cols-2">
          {snapshot.results.map(item => <article key={item.provider} className="border border-[#1a2330] bg-[#0a0e14] p-4">
            <div className="flex items-start justify-between gap-3"><h2 className="text-base font-semibold">{item.provider}</h2><span className={"border px-2 py-1 font-mono text-[9px] uppercase tracking-wider " + style[item.status]}>{item.status}</span></div>
            <p className="mt-3 text-sm leading-5 text-[#a8b3c2]">{item.summary}</p>
            <p className="mt-2 text-[10px] text-[#5a6675]">Source: {item.source} · Checked: {new Date(item.checkedAt).toLocaleString()}</p>
            {item.details !== undefined && <details className="mt-4"><summary className="cursor-pointer text-xs text-[#00d9ff]">Evidence details</summary><pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words border border-[#1a2330] bg-[#030508] p-3 text-[10px] leading-4 text-[#a8b3c2]">{JSON.stringify(item.details, null, 2)}</pre></details>}
          </article>)}
        </section>
      </>}
      {!snapshot && !error && <div className="mt-4 border border-dashed border-[#2a3646] p-6 text-sm text-[#5a6675]">No snapshot loaded. Enter the configured read token and refresh to query providers.</div>}
      <footer className="mt-8 border-t border-[#1a2330] pt-4 text-[10px] leading-5 text-[#5a6675]">Safety contract: no production writes, migrations, service restarts, merges, or deployments are exposed here. A provider failure is not a clean bill of health.</footer>
    </div>
  </main>;
}
