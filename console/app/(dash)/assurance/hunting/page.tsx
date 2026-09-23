"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function Hunting() {
  const [hunts, setHunts] = useState<Row[]>([]);
  const [runs, setRuns] = useState<Row[]>([]);
  const [query, setQuery] = useState("");
  const [output, setOutput] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [h, r] = await Promise.all([
        apiFetch<unknown>("/api/v1/hunts/"),
        apiFetch<unknown>("/api/v1/hunts/runs/history"),
      ]);
      setHunts(Array.isArray(h) ? h : []);
      setRuns(Array.isArray(r) ? r : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load hunting service");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function run() {
    setBusy(true);
    setError("");
    try {
      if (!query.trim()) throw new Error("Query required.");
      setOutput(await apiFetch("/api/v1/hunts/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query.trim() }),
      }));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Hunt failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Assurance</div>
          <h1 className="mt-1 text-2xl font-semibold">Threat Hunting</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Execute the bounded hunting language and retain run telemetry.</p>
        </header>

        {error && <ServiceError message={error} />}
        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <textarea value={query} onChange={e => setQuery(e.target.value)} rows={5} placeholder="Enter hunting query" className="w-full border border-[#2a3646] bg-[#030508] p-3 text-xs" />
          <button disabled={busy || !query.trim()} onClick={() => void run()} className="mt-3 h-9 border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
            {busy ? "Running…" : "Run hunt"}
          </button>
          {output !== null && <div className="mt-4 border border-[#1a2330] bg-[#05070a] p-4"><pre className="max-h-80 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(output, null, 2)}</pre></div>}
        </section>

        {loading ? <ServiceLoading /> : (
          <>
            <ServiceSection title="Saved hunts" count={hunts.length}>
              <ServiceTable rows={hunts} columns={[
                { key: "name", label: "Name" },
                { key: "query", label: "Query" },
                { key: "enabled", label: "Enabled" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No saved hunts" detail="No tenant hunting definitions are currently available." />} />
            </ServiceSection>
            <ServiceSection title="Run history" count={runs.length}>
              <ServiceTable rows={runs} columns={[
                { key: "status", label: "Status" },
                { key: "hunt_id", label: "Hunt" },
                { key: "started_at", label: "Started" },
                { key: "ended_at", label: "Ended" },
              ]} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
