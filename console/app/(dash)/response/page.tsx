"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function Response() {
  const [playbooks, setPlaybooks] = useState<Row[]>([]);
  const [runs, setRuns] = useState<Row[]>([]);
  const [actions, setActions] = useState<Row[]>([]);
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
      if (caseId.trim()) {
        const a = await apiFetch<{ items: Row[] }>(`/api/v1/console/response/cases/${encodeURIComponent(caseId.trim())}/actions`);
        setActions(Array.isArray(a.items) ? a.items : []);
      } else setActions([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load response service");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function approve(actionId: string) {\n    setBusy(true); setError(""); setMessage("");\n    try { await apiFetch(`/api/v1/console/response/actions/${encodeURIComponent(actionId)}/approve`, { method: "POST" }); setMessage("Action approved and dispatched to the execution path."); await load(); }\n    catch (e) { setError(e instanceof Error ? e.message : "Approval failed"); } finally { setBusy(false); }\n  }\n\n  async function reject(actionId: string) {\n    setBusy(true); setError(""); setMessage("");\n    try { await apiFetch(`/api/v1/console/response/actions/${encodeURIComponent(actionId)}/reject`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: "Rejected from response control" }) }); setMessage("Action rejected."); await load(); }\n    catch (e) { setError(e instanceof Error ? e.message : "Rejection failed"); } finally { setBusy(false); }\n  }\n\n  async function run() {
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
            <ServiceSection title="Case actions" count={actions.length}>
              {actions.length ? <div className="overflow-auto border border-[#1a2330]">
                <table className="w-full text-left text-[11px]">
                  <thead className="bg-[#111823] text-[9px] uppercase tracking-[.12em] text-[#5a6675]"><tr><th className="px-3 py-2">Action</th><th className="px-3 py-2">Status</th><th className="px-3 py-2">Device</th><th className="px-3 py-2">Created</th><th className="px-3 py-2">Control</th></tr></thead>
                  <tbody>{actions.map(x => <tr key={String(x.id)} className="border-t border-[#1a2330]">
                    <td className="px-3 py-2 font-mono">{String(x.action ?? "—")}</td><td className="px-3 py-2">{String(x.status ?? "—")}</td><td className="px-3 py-2 font-mono">{String(x.device_id ?? "—")}</td><td className="px-3 py-2">{String(x.created_at ?? "—")}</td>
                    <td className="px-3 py-2">{x.status === "pending_approval" ? <div className="flex gap-2"><button disabled={busy} onClick={() => void approve(String(x.id))} className="border border-[#00e07a] px-2 py-1 text-[#7df0ad] disabled:opacity-40">Approve</button><button disabled={busy} onClick={() => void reject(String(x.id))} className="border border-[#ff2d55] px-2 py-1 text-[#ff6b83] disabled:opacity-40">Reject</button></div> : <span className="text-[#5a6675]">No action</span>}</td>
                  </tr>)}</tbody>
                </table>
              </div> : <ServiceEmpty title="No case actions" detail="Enter a case UUID to inspect its persisted response actions." />}
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
