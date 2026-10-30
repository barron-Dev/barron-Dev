"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { AuthActions } from "@/components/AuthActions";

type Device = { id: string; device_key: string; platform: string; os_version: string | null; app_version: string | null; last_attestation: string; last_seen_at: string | null };
type Threat = { id: string; device_id: string; threat_type: string; severity_level: number; disposition: string; evidence_hash: string; observed_at: string };
type Journal = { id: string; contract_id: string; event_type: string; disposition: string; evidence_hash: string; current_hash: string; signer_key_id: string; persisted_at: string };
type Workspace = {
  data_state: string;
  coverage: { devices_returned: number; threats_returned: number; journal_events_returned: number; per_collection_limit: number; truncated_possible: boolean };
  devices: Device[];
  threats: Threat[];
  journal_events: Journal[];
  enforcement: { native_attestation_pipeline: string; remote_response_execution: string; client_claims_authorize_enforcement: boolean };
};
const panel = "rounded-2xl border border-white/10 bg-[#07131b]/80 p-5";
const muted = "text-xs text-[#8ca6ad]";
function stamp(value: string | null | undefined) { if (!value) return "Not recorded"; const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? "Unknown" : parsed.toLocaleString(); }

export default function CustomerMdiWorkspace() {
  const [data, setData] = useState<Workspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setLoading(true); setError("");
    try { setData(await apiFetch<Workspace>("/api/v1/mdi/workspace")); }
    catch (e) { setData(null); setError(e instanceof Error ? e.message : "Unable to load MDI workspace"); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  return <main className="cyclo-water min-h-screen text-[#e8f1f3]">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-[#02090e]/80 px-5 py-4">
      <div><a href="/customer/overview" className="font-semibold tracking-tight">CYCLOTHONE</a><span className="ml-3 text-[9px] uppercase tracking-[.18em] text-[#c2f35a]">Customer · MDI</span></div>
      <nav className="flex items-center gap-4 text-xs"><a href="/customer/overview" className="text-[#9db2b8]">Home</a><AuthActions /></nav>
    </header>
    <div className="mx-auto max-w-7xl space-y-6 px-5 py-9">
      <div className="flex flex-wrap items-end justify-between gap-4"><div><div className="text-[9px] uppercase tracking-[.2em] text-[#5b91a0]">Mobile & Digital Intelligence</div><h1 className="mt-2 text-3xl font-semibold">Device integrity</h1><p className={muted + " mt-2"}>Tenant-scoped device posture, recorded threat observations and signed evidence journal.</p></div><button onClick={() => void load()} disabled={loading} className="rounded-full border border-[#c2f35a]/30 px-4 py-2 text-xs text-[#d9f79a] disabled:opacity-50">{loading ? "Refreshing…" : "Refresh live records"}</button></div>
      {error && <div role="alert" className="rounded-xl border border-[#8e3b4a] bg-[#210d13] p-4 text-sm text-[#ff9cac]">{error}. Storage or API unavailable is not a clean security result.</div>}
      {loading && <div className={panel + " " + muted}>Loading persisted MDI records…</div>}
      {!loading && data && <>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{[["Devices",data.coverage.devices_returned],["Threat observations",data.coverage.threats_returned],["Journal events",data.coverage.journal_events_returned],["Data state",data.data_state.replaceAll("_"," ")]].map(([label,value])=><section key={String(label)} className={panel}><div className="text-[9px] uppercase tracking-[.16em] text-[#6f8992]">{label}</div><div className="mt-3 text-2xl font-semibold">{value}</div></section>)}</div>
        {data.data_state === "no_operational_records" && <section className={panel}><h2 className="font-medium">No operational records yet</h2><p className={muted + " mt-2"}>The connected store returned no MDI device, threat or journal records for this tenant. This does not mean devices are clean or monitored. Enrollment and trusted native ingestion must run before this workspace can show device posture.</p></section>}
        {data.coverage.truncated_possible && <p className="text-xs text-[#e6c47a]">At least one list reached its {data.coverage.per_collection_limit}-record display limit. This view is a recent-record window, not a complete export.</p>}
        <section className={panel}><h2 className="font-medium">Enrolled devices</h2><div className="mt-4 overflow-x-auto"><table className="w-full min-w-[680px] text-left text-xs"><thead className="text-[#78929b]"><tr><th className="pb-3">Platform</th><th>Device key</th><th>Attestation</th><th>Last seen</th></tr></thead><tbody>{data.devices.map(d=><tr key={d.id} className="border-t border-white/10"><td className="py-3">{d.platform}{d.os_version ? " "+d.os_version : ""}</td><td className="font-mono">{d.device_key.slice(0,16)}…</td><td>{d.last_attestation}</td><td>{stamp(d.last_seen_at)}</td></tr>)}</tbody></table>{!data.devices.length && <p className={muted}>No enrolled devices are recorded.</p>}</div></section>
        <section className={panel}><h2 className="font-medium">Threat observations</h2><div className="mt-4 space-y-2">{data.threats.map(t=><article key={t.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 p-3"><div><div className="text-xs">{t.threat_type.replaceAll("_"," ")}</div><div className={muted + " mt-1"}>Device {t.device_id.slice(0,8)} · {stamp(t.observed_at)}</div></div><div className="text-right"><div className="text-xs">Severity {t.severity_level}/5</div><div className={muted}>{t.disposition.replaceAll("_"," ")}</div></div></article>)}{!data.threats.length && <p className={muted}>No threat observations are recorded.</p>}</div></section>
        <section className={panel}><h2 className="font-medium">Signed evidence journal</h2><div className="mt-4 space-y-2">{data.journal_events.map(j=><article key={j.id} className="rounded-xl border border-white/10 p-3"><div className="flex flex-wrap justify-between gap-2 text-xs"><strong>{j.event_type}</strong><span className="text-[#a6c5ce]">{j.disposition}</span></div><div className={muted + " mt-2"}>{j.contract_id} · {stamp(j.persisted_at)}</div><div className="mt-2 break-all font-mono text-[10px] text-[#6f8992]">Evidence {j.evidence_hash}<br/>Chain {j.current_hash}</div></article>)}{!data.journal_events.length && <p className={muted}>No signed journal events are recorded.</p>}</div></section>
        <section className={panel}><h2 className="font-medium">Execution and assurance boundaries</h2><dl className="mt-3 grid gap-3 text-xs sm:grid-cols-3"><div><dt className="text-[#6f8992]">Native attestation</dt><dd className="mt-1">{data.enforcement.native_attestation_pipeline}</dd></div><div><dt className="text-[#6f8992]">Remote response</dt><dd className="mt-1">{data.enforcement.remote_response_execution}</dd></div><div><dt className="text-[#6f8992]">Client claim authorizes enforcement</dt><dd className="mt-1">{data.enforcement.client_claims_authorize_enforcement ? "Yes" : "No"}</dd></div></dl></section>
      </>}
    </div>
  </main>;
}
