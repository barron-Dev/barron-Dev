"use client";

import { useEffect, useMemo, useState } from "react";
import { apiDownload, apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Framework = { id?: string; framework?: string; name?: string; version?: string };
type Control = { id?: string; stable_id?: string; control_code?: string; title?: string; description?: string; framework?: string; [key: string]: unknown };
type Assurance = {
  framework?: string;
  period_start?: string;
  period_end?: string;
  overall_score?: number | null;
  controls_passing?: number;
  controls_total?: number;
  evidence_count?: number;
  [key: string]: unknown;
};
type Pack = {
  id: string;
  framework_id?: string;
  period_start?: string;
  period_end?: string;
  status?: string;
  overall_score?: number | null;
  controls_passing?: number;
  controls_total?: number;
  evidence_count?: number;
  verification_status?: string;
  created_at?: string;
  pack_sha256?: string;
  signer_kid?: string;
};
type Attestation = { id?: string; control_id?: string; statement?: string; signer_kid?: string; created_at?: string };

function fmtDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function score(value: number | null | undefined) {
  return typeof value === "number" ? `${value.toFixed(1)}%` : "—";
}

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [framework, setFramework] = useState("");
  const [controls, setControls] = useState<Control[]>([]);
  const [assurance, setAssurance] = useState<Assurance | null>(null);
  const [packs, setPacks] = useState<Pack[]>([]);
  const [selectedPack, setSelectedPack] = useState<Pack | null>(null);
  const [verification, setVerification] = useState<Record<string, unknown> | null>(null);
  const [attestation, setAttestation] = useState<Attestation | null>(null);
  const [statement, setStatement] = useState("");
  const [controlId, setControlId] = useState("");
  const [loading, setLoading] = useState(true);
  const [sectionBusy, setSectionBusy] = useState("");
  const [error, setError] = useState("");

  const selectedFramework = useMemo(
    () => frameworks.find(f => String(f.framework ?? f.id ?? "") === framework),
    [frameworks, framework],
  );

  useEffect(() => {
    void loadFrameworks();
  }, []);

  useEffect(() => {
    if (!framework) {
      setControls([]);
      setPacks([]);
      return;
    }
    void loadFrameworkData(framework);
  }, [framework]);

  async function loadFrameworks() {
    setLoading(true);
    setError("");
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
  }

  async function loadFrameworkData(value: string) {
    setSectionBusy("framework");
    setError("");
    try {
      const [controlRows, packRows] = await Promise.all([
        apiFetch<Control[]>(`/api/v1/compliance/controls?framework=${encodeURIComponent(value)}`),
        apiFetch<Pack[]>(`/api/v1/compliance/packs?framework=${encodeURIComponent(value)}`),
      ]);
      setControls(Array.isArray(controlRows) ? controlRows : []);
      setPacks(Array.isArray(packRows) ? packRows : []);
      setControlId(prev => prev && (controlRows as Control[]).some(c => String(c.stable_id ?? c.id ?? "") === prev)
        ? prev
        : String(controlRows[0]?.stable_id ?? controlRows[0]?.id ?? ""));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load compliance controls and evidence packs");
    } finally {
      setSectionBusy("");
    }
  }

  async function loadAssurance() {
    setSectionBusy("assurance");
    setError("");
    try {
      if (!framework) throw new Error("Select a compliance framework.");
      const end = new Date();
      const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
      const qs = new URLSearchParams({ framework, period_start: start.toISOString(), period_end: end.toISOString() });
      setAssurance(await apiFetch<Assurance>(`/api/v1/compliance/assurance?${qs.toString()}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load assurance");
    } finally {
      setSectionBusy("");
    }
  }

  async function runEvaluation() {
    setSectionBusy("run");
    setError("");
    try {
      const end = new Date();
      const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
      await apiFetch("/api/v1/compliance/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ framework, period_start: start.toISOString(), period_end: end.toISOString() }),
      });
      await Promise.all([loadAssurance(), loadFrameworkData(framework)]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Compliance evaluation failed");
    } finally {
      setSectionBusy("");
    }
  }

  async function buildPack() {
    setSectionBusy("pack");
    setError("");
    try {
      await apiFetch(`/api/v1/compliance/packs?framework=${encodeURIComponent(framework)}&period_days=90`, { method: "POST" });
      await loadFrameworkData(framework);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Evidence pack creation failed");
    } finally {
      setSectionBusy("");
    }
  }

  async function verifyPack(pack: Pack) {
    setSectionBusy(`verify:${pack.id}`);
    setError("");
    try {
      const result = await apiFetch<Record<string, unknown>>(`/api/v1/compliance/packs/${encodeURIComponent(pack.id)}/verify`, { method: "POST" });
      setVerification(result);
      setSelectedPack(pack);
      await loadFrameworkData(framework);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Evidence pack verification failed");
    } finally {
      setSectionBusy("");
    }
  }

  async function downloadPack(pack: Pack) {
    setSectionBusy(`download:${pack.id}`);
    setError("");
    try {
      const blob = await apiDownload(`/api/v1/compliance/packs/${encodeURIComponent(pack.id)}/download`);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `evidence-${pack.id}.zip`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Evidence pack download failed");
    } finally {
      setSectionBusy("");
    }
  }

  async function createAttestation() {
    setSectionBusy("attest");
    setError("");
    setAttestation(null);
    try {
      if (!controlId || statement.trim().length < 10) throw new Error("Select a control and enter an attestation statement of at least 10 characters.");
      const result = await apiFetch<Attestation>("/api/v1/compliance/attest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ control_id: controlId, statement: statement.trim(), snapshot_id: selectedPack?.id ?? null }),
      });
      setAttestation(result);
      setStatement("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Attestation failed");
    } finally {
      setSectionBusy("");
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-7xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Assurance</div>
          <h1 className="mt-1 text-2xl font-semibold">Compliance</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live framework controls, evaluation, evidence packs, verification and signed attestations.</p>
        </header>

        {error && <ServiceError message={error} />}

        {loading ? <ServiceLoading /> : (
          <>
            <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
              <div className="grid gap-4 md:grid-cols-[1fr_auto_auto] md:items-end">
                <label className="block text-xs text-[#8a97a8]">Framework
                  <select value={framework} onChange={e => setFramework(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm">
                    <option value="">Select framework</option>
                    {frameworks.map((f, i) => {
                      const value = String(f.framework ?? f.id ?? "");
                      return <option key={value || i} value={value}>{String(f.name ?? f.framework ?? f.id ?? "Framework")}{f.version ? ` · ${f.version}` : ""}</option>;
                    })}
                  </select>
                </label>
                <button disabled={!framework || !!sectionBusy} onClick={() => void runEvaluation()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
                  {sectionBusy === "run" ? "Running…" : "Run evaluation"}
                </button>
                <button disabled={!framework || !!sectionBusy} onClick={() => void buildPack()} className="h-9 rounded border border-[#2a3646] px-4 text-xs text-[#e8eef6] disabled:opacity-40">
                  {sectionBusy === "pack" ? "Building…" : "Build evidence pack"}
                </button>
              </div>
              {selectedFramework && <div className="mt-3 text-[11px] text-[#5a6675]">{selectedFramework.name ?? selectedFramework.framework} · {selectedFramework.version ?? "version not specified"}</div>}
              {!frameworks.length && <ServiceEmpty title="No compliance frameworks available" detail="The live compliance catalog returned no frameworks." />}
            </section>

            {framework && (
              <>
                <ServiceSection title="Control coverage" count={controls.length}>
                  {sectionBusy === "framework" && !controls.length ? <ServiceLoading label="Loading live controls and evidence packs…" /> : controls.length ? (
                    <ServiceTable rows={controls} columns={[
                      { key: "control_code", label: "Control" },
                      { key: "title", label: "Requirement" },
                      { key: "stable_id", label: "Stable ID" },
                    ]} />
                  ) : <ServiceEmpty title="No controls returned" detail="This framework has no tenant-visible controls." />}
                </ServiceSection>

                <ServiceSection title="Assurance">
                  <div className="flex flex-wrap items-center gap-2">
                    <button disabled={!!sectionBusy} onClick={() => void loadAssurance()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
                      {sectionBusy === "assurance" ? "Loading…" : "Refresh 24h assurance"}
                    </button>
                    {assurance && <span className="text-[11px] text-[#5a6675]">{fmtDate(assurance.period_start)} → {fmtDate(assurance.period_end)}</span>}
                  </div>
                  {assurance && (
                    <div className="mt-4 grid gap-3 sm:grid-cols-4">
                      <Metric label="Overall score" value={score(assurance.overall_score)} />
                      <Metric label="Controls passing" value={`${assurance.controls_passing ?? "—"} / ${assurance.controls_total ?? "—"}`} />
                      <Metric label="Evidence" value={String(assurance.evidence_count ?? "—")} />
                      <Metric label="Framework" value={String(assurance.framework ?? framework)} />
                    </div>
                  )}
                  {!assurance && <ServiceEmpty title="No assurance loaded" detail="Run or refresh the 24-hour assurance window to inspect the live result." />}
                </ServiceSection>

                <ServiceSection title="Evidence packs" count={packs.length}>
                  {packs.length ? (
                    <ServiceTable rows={packs} columns={[
                      { key: "created_at", label: "Created" },
                      { key: "status", label: "Status" },
                      { key: "verification_status", label: "Verification" },
                      { key: "controls_passing", label: "Passing" },
                      { key: "controls_total", label: "Total" },
                      { key: "evidence_count", label: "Evidence" },
                      { key: "pack_sha256", label: "Pack SHA-256" },
                    ]} />
                  ) : <ServiceEmpty title="No evidence packs" detail="No live evidence snapshot exists for this framework yet." />}
                  {packs.length > 0 && (
                    <div className="mt-4 flex flex-wrap gap-2">
                      {packs.slice(0, 10).map(pack => (
                        <div key={pack.id} className={`flex items-center gap-2 border border-[#1a2330] px-3 py-2 text-[10px] ${selectedPack?.id === pack.id ? "border-[#00d9ff]" : ""}`}>
                          <button onClick={() => setSelectedPack(pack)} className="text-left font-mono text-[#8a97a8]">{pack.id}</button>
                          <button disabled={!!sectionBusy} onClick={() => void verifyPack(pack)} className="text-[#00d9ff] disabled:opacity-40">
                            {sectionBusy === `verify:${pack.id}` ? "Verifying…" : "Verify"}
                          </button>
                          <button disabled={!!sectionBusy} onClick={() => void downloadPack(pack)} className="text-[#e8eef6] disabled:opacity-40">
                            {sectionBusy === `download:${pack.id}` ? "Downloading…" : "Download"}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </ServiceSection>

                {verification && selectedPack && (
                  <ServiceSection title="Verification result">
                    <div className="grid gap-3 sm:grid-cols-3">
                      <Metric label="Verified" value={String(verification.verified ?? "—")} />
                      <Metric label="Pack SHA-256" value={String(verification.pack_sha256 ?? "—")} />
                      <Metric label="Signer" value={String(verification.signer_kid ?? "—")} />
                    </div>
                  </ServiceSection>
                )}

                <ServiceSection title="Signed attestation">
                  <div className="grid gap-4 md:grid-cols-[260px_1fr_auto] md:items-end">
                    <label className="text-xs text-[#8a97a8]">Control
                      <select value={controlId} onChange={e => setControlId(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm">
                        <option value="">Select control</option>
                        {controls.map((control, i) => {
                          const value = String(control.stable_id ?? control.id ?? "");
                          return <option key={value || i} value={value}>{String(control.control_code ?? value)} — {String(control.title ?? control.description ?? "Control")}</option>;
                        })}
                      </select>
                    </label>
                    <label className="text-xs text-[#8a97a8]">Statement
                      <input value={statement} onChange={e => setStatement(e.target.value)} minLength={10} maxLength={2000} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" placeholder="State the tenant's attestation for this control." />
                    </label>
                    <button disabled={!!sectionBusy || !controlId || statement.trim().length < 10} onClick={() => void createAttestation()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
                      {sectionBusy === "attest" ? "Signing…" : "Sign attestation"}
                    </button>
                  </div>
                  {attestation && <div className="mt-4 border border-[#1a2330] p-3 text-[11px] text-[#8a97a8]">Attestation recorded: <span className="font-mono text-[#e8eef6]">{attestation.id ?? "created"}</span> · signer {attestation.signer_kid ?? "—"}</div>}
                </ServiceSection>
              </>
            )}
          </>
        )}
      </div>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="border border-[#1a2330] bg-[#080c11] p-4"><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{label}</div><div className="mt-1 truncate font-mono text-sm text-[#e8eef6]" title={value}>{value}</div></div>;
}
