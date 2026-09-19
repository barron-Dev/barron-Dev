"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";

type Framework = { id?: string; framework?: string; name?: string; version?: string; [key: string]: unknown };
type Assurance = { [key: string]: unknown };

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [framework, setFramework] = useState("");
  const [assurance, setAssurance] = useState<Assurance | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const rows = await apiFetch<Framework[]>("/api/v1/compliance/frameworks");
        setFrameworks(rows);
        const first = rows[0]?.framework ?? rows[0]?.id;
        if (typeof first === "string") setFramework(first);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load compliance frameworks");
      }
    })();
  }, []);

  async function loadAssurance() {
    setBusy(true);
    setError("");
    setAssurance(null);
    try {
      if (!framework) throw new Error("Select a compliance framework.");
      const end = new Date();
      const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
      const qs = new URLSearchParams({
        framework,
        period_start: start.toISOString(),
        period_end: end.toISOString(),
      });
      setAssurance(await apiFetch<Assurance>(`/api/v1/compliance/assurance?${qs.toString()}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load assurance");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-5xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Assurance</div>
          <h1 className="mt-1 text-2xl font-semibold">Compliance</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live tenant-scoped assurance data from the Cyclothone compliance service.</p>
        </header>
        <section className="border border-[#1a2330] bg-[#0a0e14] p-5 space-y-4">
          <label className="block text-xs text-[#8a97a8]">Framework
            <select value={framework} onChange={e => setFramework(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm">
              {frameworks.map((f, i) => {
                const value = String(f.framework ?? f.id ?? "");
                return <option key={value || i} value={value}>{String(f.name ?? f.framework ?? f.id ?? "Framework")}{f.version ? ` · ${f.version}` : ""}</option>;
              })}
            </select>
          </label>
          <button disabled={busy || !framework} onClick={() => void loadAssurance()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-50">
            {busy ? "Loading…" : "Load assurance"}
          </button>
          {error && <div role="alert" className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
        </section>
        {assurance && <section className="border border-[#1a2330] bg-[#0a0e14] p-5"><pre className="whitespace-pre-wrap break-words text-xs">{JSON.stringify(assurance, null, 2)}</pre></section>}
      </div>
    </main>
  );
}
