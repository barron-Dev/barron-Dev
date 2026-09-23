"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Framework = { id?: string; framework?: string; name?: string; version?: string; [key: string]: unknown };
type Assurance = Record<string, unknown>;

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [framework, setFramework] = useState("");
  const [assurance, setAssurance] = useState<Assurance | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      try {
        const rows = await apiFetch<Framework[]>("/api/v1/compliance/frameworks");
        setFrameworks(Array.isArray(rows) ? rows : []);
        const first = rows[0]?.framework ?? rows[0]?.id;
        if (typeof first === "string") setFramework(first);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load compliance frameworks");
      } finally {
        setLoading(false);
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
      const qs = new URLSearchParams({ framework, period_start: start.toISOString(), period_end: end.toISOString() });
      setAssurance(await apiFetch<Assurance>(`/api/v1/compliance/assurance?${qs.toString()}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load assurance");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Assurance</div>
          <h1 className="mt-1 text-2xl font-semibold">Compliance</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Tenant-scoped frameworks and assurance results from the live compliance service.</p>
        </header>

        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <>
            <section className="border border-[#1a2330] bg-[#0a0e14] p-5 space-y-4">
              <label className="block text-xs text-[#8a97a8]">Framework
                <select value={framework} onChange={e => setFramework(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm">
                  <option value="">Select framework</option>
                  {frameworks.map((f, i) => {
                    const value = String(f.framework ?? f.id ?? "");
                    return <option key={value || i} value={value}>{String(f.name ?? f.framework ?? f.id ?? "Framework")}{f.version ? ` · ${f.version}` : ""}</option>;
                  })}
                </select>
              </label>
              <button disabled={busy || !framework} onClick={() => void loadAssurance()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
                {busy ? "Loading…" : "Load assurance"}
              </button>
              {!frameworks.length && <ServiceEmpty title="No compliance frameworks available" detail="The compliance catalog returned no frameworks for this tenant." />}
            </section>

            {assurance && <ServiceSection title="Assurance result">
              <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-words text-xs text-[#8a97a8]">{JSON.stringify(assurance, null, 2)}</pre>
            </ServiceSection>}

            {!assurance && !!frameworks.length && <ServiceSection title="Framework catalog" count={frameworks.length}>
              <ServiceTable rows={frameworks as Record<string, unknown>[]} columns={[
                { key: "framework", label: "Framework" },
                { key: "name", label: "Name" },
                { key: "version", label: "Version" },
              ]} />
            </ServiceSection>}
          </>
        )}
      </div>
    </main>
  );
}
