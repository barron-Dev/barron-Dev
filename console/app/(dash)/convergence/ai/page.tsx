"use client";

import { useState } from "react";
import { startAIRun, type AIRunStart } from "../../../lib/api";

export default function AISecurityPage() {
  const [missionId, setMissionId] = useState("");
  const [missionVersion, setMissionVersion] = useState("1");
  const [missionHash, setMissionHash] = useState("");
  const [workloadLayer, setWorkloadLayer] = useState("GENERAL");
  const [risk, setRisk] = useState<"LOW"|"MEDIUM"|"HIGH"|"CRITICAL">("LOW");
  const [input, setInput] = useState("");
  const [run, setRun] = useState<AIRunStart | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function execute() {
    setBusy(true);
    setError("");
    setRun(null);
    try {
      if (!missionId || !missionHash || !input) throw new Error("Mission ID, mission hash, and input are required.");
      const result = await startAIRun({
        workload_layer: workloadLayer,
        risk_level: risk,
        required_capabilities: [],
        mission_id: missionId,
        mission_version: Number(missionVersion),
        mission_hash: missionHash,
        idempotency_token: crypto.randomUUID(),
        correlation_id: crypto.randomUUID(),
      });
      setRun(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "AI run could not be started");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-4xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Convergence</div>
          <h1 className="mt-1 text-2xl font-semibold">AI Security Runtime</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Route and start a canonical AI execution. Model and provider authority remain server-derived.</p>
        </header>

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5 space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="text-xs text-[#8a97a8]">Workload layer
              <select value={workloadLayer} onChange={e=>setWorkloadLayer(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm">
                {["GENERAL","CUSTOMER_OPERATIONS","REASONING","SECURITY","WEB_RESEARCH","THREAT_INTELLIGENCE","DARK_WEB","CRITICAL"].map(x=><option key={x}>{x}</option>)}
              </select>
            </label>
            <label className="text-xs text-[#8a97a8]">Risk
              <select value={risk} onChange={e=>setRisk(e.target.value as typeof risk)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm">
                {["LOW","MEDIUM","HIGH","CRITICAL"].map(x=><option key={x}>{x}</option>)}
              </select>
            </label>
            <label className="text-xs text-[#8a97a8]">Mission ID
              <input value={missionId} onChange={e=>setMissionId(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" />
            </label>
            <label className="text-xs text-[#8a97a8]">Mission version
              <input type="number" min="1" value={missionVersion} onChange={e=>setMissionVersion(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" />
            </label>
          </div>
          <label className="block text-xs text-[#8a97a8]">Mission SHA-256
            <input value={missionHash} onChange={e=>setMissionHash(e.target.value)} placeholder="64 lowercase hex characters" className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 font-mono text-xs" />
          </label>
          <label className="block text-xs text-[#8a97a8]">Input
            <textarea value={input} onChange={e=>setInput(e.target.value)} rows={5} className="mt-1 w-full border border-[#2a3646] bg-[#030508] p-2 text-sm" placeholder="Execution input is supplied to the provider after canonical run authorization." />
          </label>
          <button disabled={busy} onClick={()=>void execute()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-50">{busy ? "Starting…" : "Start canonical AI run"}</button>
          {error && <div role="alert" className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
        </section>

        {run && <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <div className="text-xs uppercase tracking-[.12em] text-[#5a6675]">Canonical run admitted</div>
          <dl className="mt-3 grid gap-3 md:grid-cols-2">
            {Object.entries(run).map(([key,value])=><div key={key}><dt className="text-[10px] uppercase text-[#5a6675]">{key}</dt><dd className="mt-1 break-all font-mono text-xs">{String(value)}</dd></div>)}
          </dl>
        </section>}
      </div>
    </main>
  );
}
