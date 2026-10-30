"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Receipt = { id: string; assessment_id: string; control_id: string; probe_id: string; probe_version: string; status: string; coverage: number; receipt_digest: string; signer_key_id: string; issued_at: string; };
type Control = { id: string; stable_id?: string | null; framework: string; control_code: string; title: string; };\ntype FeedRun = { source: string; status: string; completed_at?: string | null; records_upserted: number; source_version?: string | null; error_code?: string | null; };\ntype SovereignFramework = { framework_key: string; country_iso: string; framework_name: string; framework_version: string; authority_name: string; source_url: string; caveats?: string | null; };\ntype SovereignMapping = { framework_key: string; cyclothone_control_id: string; external_control_id: string; external_control_title: string; mapping_method: string; mapping_confidence: number | null; review_status: string; source_version: string; };

export default function DeveloperCompliancePage() {
  const [framework, setFramework] = useState("soc2");
  const [controls, setControls] = useState<Control[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [verified, setVerified] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");\n  const [feeds, setFeeds] = useState<Record<string, FeedRun>>({});\n  const [sovereign, setSovereign] = useState<SovereignFramework[]>([]);\n  const [mappings, setMappings] = useState<SovereignMapping[]>([]);\n  const [country, setCountry] = useState("US");\n  const [riskCve, setRiskCve] = useState("");\n  const [riskControl, setRiskControl] = useState("");\n  const [riskResult, setRiskResult] = useState<Record<string, unknown> | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [controlRows, receiptRows] = await Promise.all([
        apiFetch<Control[]>(`/api/v1/compliance/controls?framework=${encodeURIComponent(framework)}`),
        apiFetch<Receipt[]>("/api/v1/compliance/effectiveness-receipts?limit=100"),
      ]);
      setControls(controlRows); setReceipts(receiptRows);\n      const [feedResult, frameworkResult, mappingResult] = await Promise.allSettled([\n        apiFetch<{ sources: Record<string, FeedRun> }>("/api/v1/compliance/global-intelligence/status"),\n        apiFetch<SovereignFramework[]>("/api/v1/compliance/sovereign-frameworks?country_iso=" + country),\n        apiFetch<SovereignMapping[]>("/api/v1/compliance/sovereign-framework-mappings"),\n      ]);\n      if (feedResult.status === "fulfilled") setFeeds(feedResult.value.sources ?? {});\n      if (frameworkResult.status === "fulfilled") setSovereign(frameworkResult.value ?? []);\n      if (mappingResult.status === "fulfilled") setMappings(mappingResult.value ?? []);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load CSA records"); }
    finally { setLoading(false); }
  }, [framework, country]);

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

  async function calculateRisk() {\n    setError(""); setRiskResult(null);\n    try {\n      const params = new URLSearchParams({ control_id: riskControl || controls[0]?.stable_id || controls[0]?.control_code || "CSA.CONTROL", asset_criticality: "3", control_exposure: "3" });\n      if (riskCve.trim()) params.set("cve_id", riskCve.trim());\n      const result = await apiFetch<Record<string, unknown>>("/api/v1/compliance/global-risk?" + params.toString());\n      setRiskResult(result);\n    } catch (e) { setError(e instanceof Error ? e.message : "Global risk calculation unavailable"); }\n  }\n\n  async function verify(id: string) {
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
      <section className="mt-8 grid gap-4 lg:grid-cols-2">
        <article className="border border-[#1a2735] bg-[#0a1018] p-4">
          <div className="font-mono text-[10px] tracking-[.16em] text-[#00d9ff]">GLOBAL THREAT INTELLIGENCE</div>
          <h2 className="mt-2 text-lg font-semibold">Live exploit feeds</h2>
          <p className="mt-1 text-xs text-[#8a97a8]">Official CISA KEV and FIRST EPSS observations. A failed or stale feed is unknown, never a clean result.</p>
          <div className="mt-4 space-y-2">{["cisa_kev", "first_epss"].map(source => {
            const feed = feeds[source];
            const countText = feed ? String(feed.records_upserted) + " records · " + (feed.completed_at ? new Date(feed.completed_at).toLocaleString() : "no completion time") : "No successful sync evidence";
            return <div key={source} className="flex flex-wrap items-center justify-between gap-2 border-t border-[#1a2735] pt-3 text-xs">
              <span className="font-mono">{source === "cisa_kev" ? "CISA KEV" : "FIRST EPSS"}</span>
              <span className={feed?.status === "succeeded" ? "text-[#00e59b]" : "text-[#ffc45c]"}>{feed?.status ?? "Not synced / unavailable"}</span>
              <span className="text-[#718095]">{countText}</span>
            </div>;
          })}</div>
        </article>
        <article className="border border-[#1a2735] bg-[#0a1018] p-4">
          <div className="font-mono text-[10px] tracking-[.16em] text-[#00d9ff]">SOVEREIGN COMPLIANCE MAPPER</div>
          <h2 className="mt-2 text-lg font-semibold">National framework registry</h2>
          <div className="mt-3 flex gap-2"><select value={country} onChange={e => setCountry(e.target.value)} className="border border-[#26384a] bg-[#05070a] px-3 py-2 text-xs"><option value="US">United States</option><option value="DE">Germany</option><option value="CN">China</option><option value="RU">Russia</option></select><span className="self-center text-[10px] text-[#718095]">{sovereign.length} registered frameworks</span></div>
          <div className="mt-3 space-y-2">{sovereign.length === 0 ? <p className="text-xs text-[#8a97a8]">Framework registry not yet available or no entries for this jurisdiction.</p> : sovereign.map(item => <div key={item.framework_key} className="border-t border-[#1a2735] pt-3"><div className="text-sm">{item.framework_name} <span className="text-[10px] text-[#718095]">{item.framework_version}</span></div><div className="mt-1 text-[10px] text-[#718095]">{item.authority_name} · {item.framework_key}</div><a className="mt-1 inline-block text-[10px] text-[#00d9ff]" href={item.source_url} target="_blank" rel="noreferrer">Official source</a>{item.caveats && <p className="mt-1 text-[10px] text-[#8a97a8]">{item.caveats}</p>}</div>)}</div>
        </article>
      </section>
      <section className="mt-4 border border-[#1a2735] bg-[#0a1018] p-4">
        <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-lg font-semibold">Sovereign control crosswalks</h2><span className="text-[10px] text-[#718095]">{mappings.length} mappings · {mappings.filter(item => item.review_status === "reviewed").length} reviewed</span></div>
        <p className="mt-1 text-xs text-[#8a97a8]">Candidate mappings remain explicitly unreviewed; no regulatory equivalence is implied.</p>
        {mappings.length === 0 ? <p className="mt-3 text-xs text-[#8a97a8]">No control crosswalks have been published.</p> : <div className="mt-3 overflow-x-auto"><table className="w-full min-w-[640px] text-left text-xs"><thead className="text-[10px] uppercase text-[#718095]"><tr><th className="p-2">Framework</th><th className="p-2">Cyclothone control</th><th className="p-2">External reference</th><th className="p-2">Review</th></tr></thead><tbody>{mappings.map((item, index) => <tr key={item.framework_key + item.cyclothone_control_id + item.external_control_id + index} className="border-t border-[#1a2735]"><td className="p-2 font-mono">{item.framework_key}</td><td className="p-2 font-mono">{item.cyclothone_control_id}</td><td className="p-2">{item.external_control_id} · {item.external_control_title}</td><td className="p-2 text-[#ffc45c]">{item.review_status} / {item.mapping_method}</td></tr>)}</tbody></table></div>}
      </section>
      <section className="mt-8 border border-[#1a2735] bg-[#0a1018] p-4">
        <div className="font-mono text-[10px] tracking-[.16em] text-[#00d9ff]">DETERMINISTIC THREAT PRIORITIZATION</div>
        <h2 className="mt-2 text-lg font-semibold">Global CVE risk indicator</h2>
        <p className="mt-1 text-xs text-[#8a97a8]">Uses CVSS, asset criticality, control exposure and source-attributed KEV/EPSS. EPSS is CVE-level 30-day exploitation probability, not tenant breach probability.</p>
        <div className="mt-3 flex flex-wrap gap-2"><input value={riskControl} onChange={e => setRiskControl(e.target.value)} placeholder="Control stable ID (optional)" className="min-w-[220px] border border-[#26384a] bg-[#05070a] px-3 py-2 text-xs" /><input value={riskCve} onChange={e => setRiskCve(e.target.value)} placeholder="CVE-YYYY-NNNN" className="border border-[#26384a] bg-[#05070a] px-3 py-2 text-xs" /><button onClick={() => void calculateRisk()} className="border border-[#00d9ff]/50 px-3 py-2 text-xs text-[#00d9ff]">Calculate risk</button></div>
        {riskResult && <pre className="mt-3 overflow-x-auto border border-[#26384a] bg-[#05070a] p-3 text-[10px] text-[#c4d0dd]">{JSON.stringify(riskResult, null, 2)}</pre>}
      </section>
      <section className="mt-8"><h2 className="mb-3 text-lg font-semibold">Effectiveness receipts</h2>{receipts.length === 0 ? <div className="border border-dashed border-[#344253] p-6 text-sm text-[#8a97a8]">No persisted receipts yet. Collector status is not represented as effectiveness proof.</div> : <div className="space-y-3">{receipts.map(r => <article key={r.id} className="border border-[#1a2735] bg-[#0a1018] p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="font-mono text-xs text-[#00d9ff]">{r.control_id}</div><div className="mt-1 text-sm">{r.probe_id} <span className="text-xs text-[#718095]">v{r.probe_version}</span></div><div className="mt-1 text-[10px] text-[#718095]">{new Date(r.issued_at).toLocaleString()} · {(r.coverage * 100).toFixed(1)}% coverage · {r.signer_key_id}</div></div><span className="border border-[#344253] px-2 py-1 text-xs">{r.status}</span></div><div className="mt-3 break-all font-mono text-[10px] text-[#718095]">{r.receipt_digest}</div><div className="mt-3 flex items-center gap-3"><button onClick={() => void verify(r.id)} className="border border-[#00d9ff]/40 px-3 py-2 text-[11px] text-[#00d9ff]">Verify Ed25519 signature</button>{verified[r.id] !== undefined && <span className={verified[r.id] ? "text-xs text-[#00e59b]" : "text-xs text-[#ff6b83]"}>{verified[r.id] ? "Verified" : "Invalid signature"}</span>}</div></article>)}</div>}</section>
    </>}
  </div></main>;
}
