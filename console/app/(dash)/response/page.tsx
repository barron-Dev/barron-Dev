"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function Response() {
  const [playbooks, setPlaybooks] = useState<Row[]>([]);
  const [runs, setRuns] = useState<Row[]>([]);
  const [caseId, setCaseId] = useState("");
  const [playbook, setPlaybook] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [p, r] = await Promise.all([
        apiFetch<{ items: Row[] }>("/api/v1/console/response/playbooks"),
        apiFetch<{ items: Row[] }>("/api/v1/console/response/runs"),
      ]);
      setPlaybooks(Array.isArray(p.items) ? p.items : []);
      setRuns(Array.isArray(r.items) ? r.items : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load response service");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function run() {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      if (!playbook || !caseId.trim()) throw new Error("Playbook and case ID are required.");
      await apiFetch(`/api/v1/console/response/playbooks/${encodeURIComponent(playbook)}/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: caseId.trim(), dry_run: dryRun }),
      });
      setMessage(dryRun ? "Dry run accepted." : "Response run accepted.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Response run failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Operations</div>
          <h1 className="mt-1 text-2xl font-semibold">Response</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live playbooks, controlled execution and response history.</p>
        </header>

        {error && <ServiceError message={error} />}
        {message && <div className="border border-[#00e07a]/30 bg-[#00e07a]/5 p-3 text-xs text-[#7df0ad]" role="status">{message}</div>}

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <h2 className="font-semibold">Run playbook</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            <select value={playbook} onChange={e => setPlaybook(e.target.value)} disabled={loading || !playbooks.length} className="h-9 border border-[#2a3646] bg-[#030508] px-2 text-xs">
              <option value="">{loading ? "Loading playbooks…" : "Select playbook"}</option>
              {playbooks.map(x => <option key={String(x.id)} value={String(x.id)}>{String(x.name ?? x.id)}</option>)}
            </select>
            <input value={caseId} onChange={e => setCaseId(e.target.value)} placeholder="Case UUID" className="h-9 border border-[#2a3646] bg-[#030508] px-2 text-xs" />
            <label className="flex items-center gap-2 text-xs">
              <input type="checkbox" checked={dryRun} onChange={e => setDryRun(e.target.checked)} />
              Dry run
            </label>
          </div>
          <button disabled={busy || loading || !playbook || !caseId.trim()} onClick={() => void run()} className="mt-3 h-9 border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
            {busy ? "Running…" : "Run"}
          </button>
          {!loading && !playbooks.length && <div className="mt-3 text-xs text-[#5a6675]">No tenant playbooks are currently available.</div>}
        </section>

        {loading ? <ServiceLoading /> : (
          <>
            <ServiceSection title="Playbooks" count={playbooks.length}>
              {playbooks.length ? (
                <ServiceTable rows={playbooks} columns={[
                  { key: "name", label: "Name" },
                  { key: "enabled", label: "Enabled" },
                  { key: "trigger", label: "Trigger" },
                  { key: "updated_at", label: "Updated" },
                ]} />
              ) : <ServiceEmpty title="No playbooks" detail="Create or provision a real tenant playbook before running response." />}
            </ServiceSection>
            <ServiceSection title="Runs" count={runs.length}>
              <ServiceTable rows={runs} columns={[
                { key: "status", label: "Status" },
                { key: "playbook_id", label: "Playbook" },
                { key: "case_id", label: "Case" },
                { key: "device_id", label: "Device" },
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
