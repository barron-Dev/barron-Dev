"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Control = {
  control_id: string;
  status: string;
  score: number | null;
  last_evaluated: string | null;
  freshness_status?: string | null;
  evidence_valid_until?: string | null;
};

type Receipt = {
  id: string;
  assessment_id: string;
  control_id: string;
  probe_id: string;
  probe_version: string;
  status: "effective" | "ineffective" | "partial" | "unknown";
  coverage: number;
  receipt_digest: string;
  signer_key_id: string;
  issued_at: string;
};

type Verification = { verified: boolean; receipt_digest: string; signer_key_id: string; };

function statusTone(value: string) {
  if (value === "effective" || value === "passing" || value === "fresh") return "text-[#00e59b] border-[#00e59b]/30 bg-[#00e59b]/5";
  if (value === "ineffective" || value === "failing" || value === "stale") return "text-[#ff6b83] border-[#ff6b83]/30 bg-[#ff6b83]/5";
  if (value === "partial" || value === "warning") return "text-[#ffc45c] border-[#ffc45c]/30 bg-[#ffc45c]/5";
  return "text-[#9ba8b8] border-[#344253] bg-[#344253]/10";
}

export default function CustomerCompliancePage() {
  const [controls, setControls] = useState<Control[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [verified, setVerified] = useState<Record<string, Verification | null>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [checking, setChecking] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [controlData, receiptData] = await Promise.all([
        apiFetch<{ controls: Control[] }>("/api/v1/compliance/customer/effectiveness"),
        apiFetch<Receipt[]>("/api/v1/compliance/customer/effectiveness-receipts"),
      ]);
      setControls(controlData.controls ?? []);
      setReceipts(receiptData ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "CSA assurance data is unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function verify(id: string) {
    setChecking(id);
    try {
      const result = await apiFetch<Verification>(`/api/v1/compliance/customer/effectiveness-receipts/${encodeURIComponent(id)}/verify`);
      setVerified(current => ({ ...current, [id]: result }));
    } catch (e) {
      setVerified(current => ({ ...current, [id]: null }));
      setError(e instanceof Error ? e.message : "Receipt verification unavailable");
    } finally {
      setChecking(null);
    }
  }

  const counts = controls.reduce((acc, row) => {
    const key = ["effective", "passing"].includes(row.status) ? "effective"
      : ["ineffective", "failing"].includes(row.status) ? "ineffective"
      : row.status === "partial" ? "partial" : "unknown";
    acc[key] += 1;
    return acc;
  }, { effective: 0, ineffective: 0, partial: 0, unknown: 0 });

  return (
    <main className="min-h-screen bg-[#05070a] px-5 py-8 text-[#e8eef6] md:px-8">
      <div className="mx-auto max-w-7xl">
        <header className="flex flex-wrap items-end justify-between gap-4 border-b border-[#1a2735] pb-6">
          <div>
            <div className="font-mono text-[10px] tracking-[.2em] text-[#00d9ff]">CYCLOTHONE / CUSTOMER ASSURANCE</div>
            <h1 className="mt-2 text-3xl font-semibold">Security Control Assurance</h1>
            <p className="mt-2 max-w-2xl text-sm text-[#8a97a8]">Control observations, evidence freshness and cryptographically verifiable effectiveness receipts for your organization.</p>
          </div>
          <button onClick={() => void load()} className="border border-[#26384a] px-4 py-2 text-xs text-[#c4d0dd] hover:border-[#00d9ff]">Refresh data</button>
        </header>

        {error && <div className="mt-5 border border-[#ff6b83]/30 bg-[#ff6b83]/5 p-3 text-sm text-[#ff9aaa]">{error}</div>}

        {loading ? <div className="py-12 text-sm text-[#8a97a8]">Loading tenant assurance data…</div> : <>
          <section className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {Object.entries(counts).map(([key, value]) => <div key={key} className="border border-[#1a2735] bg-[#0a1018] p-4">
              <div className="text-[10px] uppercase tracking-[.16em] text-[#718095]">{key} controls</div>
              <div className="mt-2 text-3xl font-semibold tabular-nums">{value}</div>
            </div>)}
          </section>

          <section className="mt-8">
            <div className="mb-3 flex items-center justify-between"><h2 className="text-lg font-semibold">Control effectiveness map</h2><span className="text-[10px] text-[#718095]">{controls.length} tenant-scoped records</span></div>
            {controls.length === 0 ? <div className="border border-dashed border-[#344253] p-6 text-sm text-[#8a97a8]">No control observations have been recorded for this tenant. No pass status is inferred from missing data.</div> :
              <div className="overflow-x-auto border border-[#1a2735]"><table className="w-full min-w-[760px] text-left text-xs">
                <thead className="bg-[#0b121c] text-[10px] uppercase tracking-[.12em] text-[#718095]"><tr><th className="p-3">Control</th><th className="p-3">Observed status</th><th className="p-3">Score</th><th className="p-3">Freshness</th><th className="p-3">Last evaluated</th></tr></thead>
                <tbody>{controls.map((row, i) => <tr key={row.control_id + i} className="border-t border-[#1a2735]"><td className="p-3 font-mono">{row.control_id}</td><td className="p-3"><span className={`rounded border px-2 py-1 ${statusTone(row.status)}`}>{row.status}</span></td><td className="p-3 tabular-nums">{row.score == null ? "Unknown" : row.score}</td><td className="p-3"><span className={`rounded border px-2 py-1 ${statusTone(row.freshness_status ?? "unknown")}`}>{row.freshness_status ?? "unknown"}</span>{row.evidence_valid_until && <div className="mt-1 text-[10px] text-[#718095]">Until {new Date(row.evidence_valid_until).toLocaleString()}</div>}</td><td className="p-3 text-[#9ba8b8]">{row.last_evaluated ? new Date(row.last_evaluated).toLocaleString() : "Not evaluated"}</td></tr>)}</tbody>
              </table></div>}
          </section>

          <section className="mt-8">
            <div className="mb-3 flex items-center justify-between"><h2 className="text-lg font-semibold">Cryptographic evidence receipts</h2><span className="text-[10px] text-[#718095]">{receipts.length} receipts</span></div>
            {receipts.length === 0 ? <div className="border border-dashed border-[#344253] p-6 text-sm text-[#8a97a8]">No signed effectiveness receipts have been persisted for this tenant yet.</div> :
              <div className="space-y-3">{receipts.map(row => <article key={row.id} className="border border-[#1a2735] bg-[#0a1018] p-4">
                <div className="flex flex-wrap items-start justify-between gap-3"><div><div className="font-mono text-xs text-[#00d9ff]">{row.control_id}</div><div className="mt-1 text-sm font-medium">{row.probe_id} <span className="text-xs text-[#718095]">v{row.probe_version}</span></div><div className="mt-1 text-[10px] text-[#718095]">Issued {new Date(row.issued_at).toLocaleString()} · coverage {(row.coverage * 100).toFixed(1)}%</div></div><span className={`rounded border px-2 py-1 text-xs ${statusTone(row.status)}`}>{row.status}</span></div>
                <div className="mt-3 break-all font-mono text-[10px] text-[#718095]">SHA-256 {row.receipt_digest}</div>
                <div className="mt-3 flex flex-wrap items-center gap-3"><button disabled={checking === row.id} onClick={() => void verify(row.id)} className="border border-[#00d9ff]/40 px-3 py-2 text-[11px] text-[#00d9ff] disabled:opacity-50">{checking === row.id ? "Verifying…" : "Verify signature"}</button>{verified[row.id] && <span className={verified[row.id]?.verified ? "text-xs text-[#00e59b]" : "text-xs text-[#ff6b83]"}>{verified[row.id]?.verified ? "Ed25519 signature verified" : "Signature verification failed"}</span>}</div>
              </article>)}</div>}
          </section>
        </>}
      </div>
    </main>
  );
}
