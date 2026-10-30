"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Receipt = { id: string; assessment_id: string; control_id: string; probe_id: string; probe_version: string; status: string; coverage: number; receipt_digest: string; signer_key_id: string; issued_at: string; };
type Control = { id: string; stable_id?: string | null; framework: string; control_code: string; title: string; };

export default function DeveloperCompliancePage() {
  const [framework, setFramework] = useState("soc2");
  const [controls, setControls] = useState<Control[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [verified, setVerified] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [controlRows, receiptRows] = await Promise.all([
        apiFetch<Control[]>(`/api/v1/compliance/controls?framework=${encodeURIComponent(framework)}`),
        apiFetch<Receipt[]>("/api/v1/compliance/effectiveness-receipts?limit=100"),
      ]);
      setControls(controlRows); setReceipts(receiptRows);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load CSA records"); }
    finally { setLoading(false); }
  }, [framework]);

  useEffect(() => { void load(); }, [load]);

  async function runAssessment() {
    setRunning(true); setError(""); setMessage("");
    try {
      const result = await apiFetch<Record<string, unknown>>("/api/v1/compliance/runs/last-24h", { method: "POST" });
      setMessage(`Assessment run created: ${String(result.id ?? result.run_id ?? "accepted")}`);
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "CSA assessment could not be started"); }
    finally { setRunning(false); }
  }

  async function verify(id: string) {
    setError("");
    try {
      const result = await apiFetch<{ verified: boolean }>(`/api/v1/compliance/effectiveness-receipts/${encodeURIComponent(id)}/verify`);
      setVerified(current => ({ ...current, [id]: result.verified }));
    } catch (e) { setError(e instanceof Error ? e.message : "Receipt verification failed"); }
  }

  return <main className="min-h-screen bg-[#05070a] px-5 py-8 text-[#e8eef6] md:px-8"><div className="mx-auto max-w-7xl">
    <header className="flex flex-wrap items-end justify-between gap-4 border-b border-[#1a2735] pb-6"><div><div className="font-mono text-[10px] tracking-[.2em] text-[#00d9ff]">CYCLOTHONE / DEVELOPER ASSURANCE</div><h1 className="mt-2 text-3xl font-semibold">Compliance Security Assurance</h1><p className="mt-2 text-sm text-[#8a97a8]">Framework controls, assessment execution and signed-effectiveness receipt verification.</p></div><div className="flex gap-2"><select value={framework} onChange={e => setFramework(e.target.value)} className="border border-[#26384a] bg-[#0a1018] px-3 py-2 text-xs"><option value="soc2">SOC 2</option><option value="iso27001">ISO 27001</option><option value="gdpr">GDPR</option><option value="hipaa">HIPAA</option><option value="pci_dss">PCI DSS</option><option value="uae_pdpl">UAE PDPL</option><option value="nigeria_ndpa">Nigeria NDPA</option></select><button onClick={() => void load()} className="border border-[#26384a] px-3 py-2 text-xs">Refresh</button><button onClick={() => void runAssessment()} disabled={running} className="border border-[#00d9ff]/50 bg-[#00d9ff]/5 px-3 py-2 text-xs text-[#00d9ff] disabled:opacity-50">{running ? "Starting…" : "Run 24h assessment"}</button></div></header>
    {error && <div className="mt-5 border border-[#ff6b83]/30 bg-[#ff6b83]/5 p-3 text-sm text-[#ff9aaa]">{error}</div>}
    {message && <div className="mt-5 border border-[#00e59b]/30 bg-[#00e59b]/5 p-3 text-sm text-[#00e59b]">{message}</div>}
    {loading ? <div className="py-12 text-sm text-[#8a97a8]">Loading live CSA records…</div> : <>
      <section className="mt-6 grid gap-3 sm:grid-cols-3"><div className="border border-[#1a2735] bg-[#0a1018] p-4"><div className="text-[10px] uppercase tracking-[.15em] text-[#718095]">Framework controls</div><div className="mt-2 text-3xl tabular-nums">{controls.length}</div></div><div className="border border-[#1a2735] bg-[#0a1018] p-4"><div className="text-[10px] uppercase tracking-[.15em] text-[#718095]">Signed receipts</div><div className="mt-2 text-3xl tabular-nums">{receipts.length}</div></div><div className="border border-[#1a2735] bg-[#0a1018] p-4"><div className="text-[10px] uppercase tracking-[.15em] text-[#718095]">Verified this session</div><div className="mt-2 text-3xl tabular-nums">{Object.values(verified).filter(Boolean).length}</div></div></section>
      <section className="mt-8"><h2 className="mb-3 text-lg font-semibold">Control catalogue · {framework.toUpperCase()}</h2>{controls.length === 0 ? <div className="border border-dashed border-[#344253] p-6 text-sm text-[#8a97a8]">No controls returned for this framework.</div> : <div className="overflow-x-auto border border-[#1a2735]"><table className="w-full min-w-[600px] text-left text-xs"><thead className="bg-[#0b121c] text-[10px] uppercase tracking-[.12em] text-[#718095]"><tr><th className="p-3">Stable ID</th><th className="p-3">Code</th><th className="p-3">Control</th></tr></thead><tbody>{controls.map(c => <tr key={c.id} className="border-t border-[#1a2735]"><td className="p-3 font-mono">{c.stable_id ?? "Stable ID pending"}</td><td className="p-3 font-mono">{c.control_code}</td><td className="p-3">{c.title}</td></tr>)}</tbody></table></div>}</section>
      <section className="mt-8"><h2 className="mb-3 text-lg font-semibold">Effectiveness receipts</h2>{receipts.length === 0 ? <div className="border border-dashed border-[#344253] p-6 text-sm text-[#8a97a8]">No persisted receipts yet. Collector status is not represented as effectiveness proof.</div> : <div className="space-y-3">{receipts.map(r => <article key={r.id} className="border border-[#1a2735] bg-[#0a1018] p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="font-mono text-xs text-[#00d9ff]">{r.control_id}</div><div className="mt-1 text-sm">{r.probe_id} <span className="text-xs text-[#718095]">v{r.probe_version}</span></div><div className="mt-1 text-[10px] text-[#718095]">{new Date(r.issued_at).toLocaleString()} · {(r.coverage * 100).toFixed(1)}% coverage · {r.signer_key_id}</div></div><span className="border border-[#344253] px-2 py-1 text-xs">{r.status}</span></div><div className="mt-3 break-all font-mono text-[10px] text-[#718095]">{r.receipt_digest}</div><div className="mt-3 flex items-center gap-3"><button onClick={() => void verify(r.id)} className="border border-[#00d9ff]/40 px-3 py-2 text-[11px] text-[#00d9ff]">Verify Ed25519 signature</button>{verified[r.id] !== undefined && <span className={verified[r.id] ? "text-xs text-[#00e59b]" : "text-xs text-[#ff6b83]"}>{verified[r.id] ? "Verified" : "Invalid signature"}</span>}</div></article>)}</div>}</section>
    </>}
  </div></main>;
}
