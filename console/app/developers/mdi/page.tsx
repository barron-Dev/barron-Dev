"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { AuthActions } from "@/components/AuthActions";

type Workspace = {
  data_state: string;
  coverage: { devices_returned: number; threats_returned: number; journal_events_returned: number; per_collection_limit: number; truncated_possible: boolean };
  integration: { required_scope: string; read_endpoint: string; customer_endpoint: string; write_contract: string };
};
const panel = "rounded-2xl border border-white/10 bg-[#07131b]/80 p-5";
const muted = "text-xs text-[#8ca6ad]";

export default function DeveloperMdiWorkspace() {
  const [data, setData] = useState<Workspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setData(await apiFetch<Workspace>("/api/v1/mdi/developer-workspace")); }
    catch (e) { setData(null); setError(e instanceof Error ? e.message : "Unable to load MDI developer workspace"); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  return <main className="cyclo-water min-h-screen text-[#e8f1f3]">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-[#02090e]/80 px-5 py-4"><div><a href="/developers" className="font-semibold tracking-tight">CYCLOTHONE</a><span className="ml-3 text-[9px] uppercase tracking-[.18em] text-[#c2f35a]">Developer · MDI</span></div><nav className="flex items-center gap-4 text-xs"><a href="/developers" className="text-[#9db2b8]">Developer home</a><AuthActions /></nav></header>
    <div className="mx-auto max-w-7xl space-y-6 px-5 py-9">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><div className="text-[9px] uppercase tracking-[.2em] text-[#5b91a0]">Mobile & Digital Intelligence</div><h1 className="mt-2 text-3xl font-semibold">Developer integration</h1><p className={muted + " mt-2"}>Tenant-bound MDI records, API contract and evidence references.</p></div><button onClick={() => void load()} disabled={loading} className="rounded-full border border-[#c2f35a]/30 px-4 py-2 text-xs text-[#d9f79a] disabled:opacity-50">{loading ? "Refreshing…" : "Refresh"}</button></div>
      {error && <div role="alert" className="rounded-xl border border-[#8e3b4a] bg-[#210d13] p-4 text-sm text-[#ff9cac]">{error}</div>}
      {loading && <section className={panel + " " + muted}>Loading tenant-scoped integration state…</section>}
      {!loading && data && <>
        <section className={panel}><div className="text-[9px] uppercase tracking-[.16em] text-[#6f8992]">Required API scope</div><div className="mt-2 font-mono text-sm">{data.integration.required_scope}</div><div className={muted + " mt-3"}>Records returned: {data.coverage.devices_returned} devices · {data.coverage.threats_returned} threat observations · {data.coverage.journal_events_returned} journal events</div></section>
        <section className={panel}><h2 className="font-medium">Read endpoints</h2><div className="mt-3 space-y-3 text-xs"><div><div className={muted}>Developer API</div><code className="mt-1 block break-all">GET {data.integration.read_endpoint}</code></div><div><div className={muted}>Customer workspace</div><code className="mt-1 block break-all">GET {data.integration.customer_endpoint}</code></div></div></section>
        <section className={panel}><h2 className="font-medium">Write and trust boundary</h2><p className={muted + " mt-2"}>{data.integration.write_contract}. Device writes are intentionally not exposed until trusted native adapters, server-side attestation verification, replay protection and signed evidence persistence are deployed.</p></section>
        <section className={panel}><h2 className="font-medium">Current operational state</h2><div className="mt-2 text-sm">{data.data_state.replaceAll("_"," ")}</div>{data.coverage.truncated_possible && <p className="mt-2 text-xs text-[#e6c47a]">Recent-record view reached its configured limit; a paginated export contract is required for complete retrieval.</p>}</section>
      </>}
    </div>
  </main>;
}
