"use client";

import { useEffect, useMemo, useState } from "react";
import { decideAdmission, getAdmissions, setApiToken, type AdmissionRecord } from "../../../lib/api";

const serviceLabels: Record<string,string> = {
  cybersecurity_assessment: "Cybersecurity Assessment",
  incident_response: "Incident Response",
  threat_intelligence: "Threat Intelligence",
  brand_protection: "Brand Protection",
  dark_web_monitoring: "Dark Web Monitoring",
  soc_mdr: "SOC / MDR",
  ai_security: "AI Security",
  physical_security: "Physical Security",
  compliance: "Compliance",
  other: "Other",
};

function fmt(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "—";
}

function statusClass(status: string) {
  if (status === "verified" || status === "approved") return "border-[#00e07a]/40 bg-[#00e07a]/10 text-[#7df0ad]";
  if (status === "rejected" || status === "suspended") return "border-[#ff2d55]/40 bg-[#ff2d55]/10 text-[#ff6b83]";
  if (status === "under_review" || status === "submitted" || status === "pending" || status === "review") return "border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffd27a]";
  return "border-[#2a3646] bg-[#111823] text-[#8a97a8]";
}

export default function AdmissionQueue() {
  const [token,setToken] = useState("");
  const [rows,setRows] = useState<AdmissionRecord[]>([]);
  const [selected,setSelected] = useState<string|null>(null);
  const [reason,setReason] = useState("");
  const [filter,setFilter] = useState("");
  const [loading,setLoading] = useState(true);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState<string|null>(null);

  async function load(t = token) {
    setLoading(true);
    setError(null);
    try {
      const result = await getAdmissions();
      setRows(result.admissions);
      if (selected && !result.admissions.some(x => x.id === selected)) setSelected(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load admission queue");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const t = sessionStorage.getItem("cyclothone_access_token") || "";
    setToken(t);
    setApiToken(t);
    void load(t);
  }, []);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(row => {
      const o = row.organization;
      return [o?.legal_name,o?.organization_type,o?.country_code,o?.website_domain,row.assurance_level,row.status,
        ...row.verifications.map(v => v.verification_type),
        ...row.service_requests.map(s => s.service_key)
      ].some(v => (v ?? "").toLowerCase().includes(q));
    });
  }, [rows,filter]);

  const active = rows.find(x => x.id === selected) ?? visible[0] ?? null;

  async function decide(decision: "approve"|"reject") {
    if (!active) return;
    if (decision === "reject" && reason.trim().length < 3) {
      setError("A rejection reason of at least 3 characters is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await decideAdmission(active.id, decision, reason);
      setReason("");
      setSelected(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Admission decision failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex h-14 items-center justify-between border-b border-[#1a2330] bg-[#0a0e14] px-5">
        <div>
          <div className="text-[9px] uppercase tracking-[.18em] text-[#5a6675]">Platform administration</div>
          <h1 className="text-base font-semibold">Customer workspace admissions</h1>
        </div>
        <div className="flex items-center gap-2">
          <a href="/" className="border border-[#2a3646] px-3 py-1.5 text-[11px] text-[#8a97a8]">Console</a>
          <button onClick={()=>void load()} disabled={loading || busy} className="border border-[#2a3646] px-3 py-1.5 text-[11px] text-[#8a97a8] disabled:opacity-40">Refresh</button>
        </div>
      </header>

      <div className="grid min-h-[calc(100vh-3.5rem)] grid-cols-1 lg:grid-cols-[360px_1fr]">
        <aside className="border-r border-[#1a2330] bg-[#0a0e14] p-4">
          <div className="mb-3 flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Pending queue</span>
            <span className="font-mono text-[11px] text-[#00d9ff]">{rows.length}</span>
          </div>
          <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter organization, service, verification…" className="mb-3 w-full border border-[#2a3646] bg-[#030508] px-3 py-2 text-[11px] outline-none focus:border-[#00d9ff]" />
          <div className="space-y-1">
            {loading && <div className="p-3 text-xs text-[#5a6675]">Loading live queue…</div>}
            {!loading && !visible.length && <div className="p-3 text-xs text-[#5a6675]">No pending admissions returned by the API.</div>}
            {visible.map(row => {
              const o=row.organization;
              return <button key={row.id} onClick={()=>setSelected(row.id)} className={"w-full border p-3 text-left "+(active?.id===row.id?"border-[#00d9ff]/60 bg-[#111823]":"border-[#1a2330] bg-[#05070a] hover:bg-[#111823]")}>
                <div className="flex items-center justify-between gap-2"><span className="truncate text-xs font-medium">{o?.legal_name || row.organization_id}</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+statusClass(row.status)}>{row.status}</span></div>
                <div className="mt-1 text-[10px] text-[#5a6675]">{o?.organization_type || "unknown"} · {o?.country_code || "—"} · submitted {fmt(row.submitted_at)}</div>
              </button>;
            })}
          </div>
        </aside>

        <section className="min-w-0 p-5">
          {error && <div role="alert" className="mb-4 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
          {!active ? <div className="flex h-full min-h-[400px] items-center justify-center border border-dashed border-[#1a2330] text-xs text-[#5a6675]">Select a pending admission to inspect the live organization record.</div> :
          <div className="space-y-4">
            <div className="border border-[#1a2330] bg-[#0a0e14] p-5">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div><div className="text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Organization</div><h2 className="mt-1 text-xl font-semibold">{active.organization?.legal_name || active.organization_id}</h2><div className="mt-1 text-xs text-[#8a97a8]">{active.organization?.organization_type} · {active.organization?.country_code || "country not provided"} · {active.organization?.website_domain || "domain not provided"}</div></div>
                <div className="text-right"><div className={"inline-block rounded border px-2 py-1 font-mono text-[10px] "+statusClass(active.organization?.verification_status || "")}>{active.organization?.verification_status || "unknown"}</div><div className="mt-2 text-[10px] text-[#5a6675]">Admission {active.status} · assurance {active.assurance_level || "registered"}</div></div>
              </div>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
                <h3 className="text-xs font-medium">Verification evidence</h3>
                <div className="mt-3 space-y-2">
                  {!active.verifications.length && <div className="text-xs text-[#5a6675]">No verification submissions are recorded.</div>}
                  {active.verifications.map(v => <div key={v.id} className="flex items-center justify-between gap-3 border-b border-[#1a2330] py-2"><div><div className="text-xs">{v.verification_type}</div><div className="font-mono text-[9px] text-[#5a6675]">{v.provider || "provider not recorded"} · {v.reference || "no reference"}</div></div><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+statusClass(v.status)}>{v.status}</span></div>)}
                </div>
              </div>

              <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
                <h3 className="text-xs font-medium">Requested services</h3>
                <div className="mt-3 space-y-2">
                  {!active.service_requests.length && <div className="text-xs text-[#5a6675]">No service requests recorded for this organization.</div>}
                  {active.service_requests.map(s => <div key={s.id} className="border-b border-[#1a2330] py-2"><div className="flex items-center justify-between gap-3"><span className="text-xs">{serviceLabels[s.service_key] || s.service_key}</span><span className="font-mono text-[9px] text-[#8a97a8]">{s.urgency} · {s.status}</span></div><div className="mt-1 line-clamp-2 text-[10px] text-[#5a6675]">{s.description}</div></div>)}
                </div>
              </div>
            </div>

            <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
              <div className="text-xs font-medium">Decision</div>
              <p className="mt-1 text-[11px] text-[#5a6675]">Approval provisions the real tenant workspace through the protected backend transaction. Rejection requires a reason.</p>
              <textarea value={reason} onChange={e=>setReason(e.target.value)} rows={3} placeholder="Decision reason (required for rejection; recommended for approval)" className="mt-3 w-full border border-[#2a3646] bg-[#030508] p-3 text-xs outline-none focus:border-[#00d9ff]" />
              <div className="mt-3 flex gap-2">
                <button disabled={busy || !active} onClick={()=>void decide("approve")} className="border border-[#00e07a]/50 px-4 py-2 text-[11px] text-[#7df0ad] disabled:opacity-40">{busy ? "Processing…" : "Approve & provision workspace"}</button>
                <button disabled={busy || !active} onClick={()=>void decide("reject")} className="border border-[#ff2d55]/50 px-4 py-2 text-[11px] text-[#ff6b83] disabled:opacity-40">Reject admission</button>
              </div>
            </div>
          </div>}
        </section>
      </div>
    </main>
  );
}
