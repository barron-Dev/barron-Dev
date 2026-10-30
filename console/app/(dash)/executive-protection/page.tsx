"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../lib/api";
import { ServiceError, ServiceLoading } from "../../../components/ServiceData";

type Assignment = {
  id: string;
  assignment_name: string;
  purpose: string;
  region_code: string;
  start_time: string;
  end_time: string;
  status: string;
  created_by: string;
  approved_by?: string | null;
};
type Row = Record<string, unknown>;

function fmt(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function ExecutiveProtectionPage() {
  const [items, setItems] = useState<Assignment[]>([]);
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [region, setRegion] = useState("");
  const [subjectRef, setSubjectRef] = useState("");
  const [authorizationRef, setAuthorizationRef] = useState("");
  const [consentHash, setConsentHash] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [findingIds, setFindingIds] = useState<Record<string, string>>({});
  const [results, setResults] = useState<Record<string, Row | null>>({});
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    setError("");
    try {
      const data = await apiFetch<{items: Assignment[]}>("/api/v1/vip-protection/assignments");
      setItems(Array.isArray(data.items) ? data.items : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load assignments");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function create() {
    setBusy("create");
    setError("");
    try {
      if (!start || !end) throw new Error("Choose the assignment start and end times.");
      await apiFetch("/api/v1/vip-protection/assignments", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({
          assignment_name: name.trim(),
          purpose: purpose.trim(),
          region_code: region.trim().toUpperCase(),
          subject_ref: subjectRef.trim(),
          authorization_ref: authorizationRef.trim(),
          consent_evidence_sha256: consentHash.trim().toLowerCase(),
          start_time: new Date(start).toISOString(),
          end_time: new Date(end).toISOString(),
        }),
      });
      setName(""); setPurpose(""); setRegion(""); setSubjectRef("");
      setAuthorizationRef(""); setConsentHash(""); setStart(""); setEnd("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Assignment creation failed");
    } finally { setBusy(""); }
  }

  async function action(id: string, kind: "approve"|"close"|"sos"|"correlate") {
    setBusy(id + ":" + kind);
    setError("");
    try {
      if (kind === "correlate") {
        const ids = (findingIds[id] || "").split(",").map(v => Number(v.trim())).filter(v => Number.isSafeInteger(v) && v > 0);
        if (!ids.length) throw new Error("Enter one or more existing tenant finding IDs.");
        const result = await apiFetch<Row>(`/api/v1/vip-protection/assignments/${id}/correlate`, {
          method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({finding_ids:ids}),
        });
        setResults(prev => ({...prev, [id]:result}));
      } else if (kind === "sos") {
        const result = await apiFetch<Row>(`/api/v1/vip-protection/assignments/${id}/sos`, {
          method:"POST", headers:{"Content-Type":"application/json"},
          body:JSON.stringify({confirm:true}),
        });
        setResults(prev => ({...prev, [id]:result}));
      } else {
        await apiFetch(`/api/v1/vip-protection/assignments/${id}/${kind}`, {method:"POST"});
      }
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : `Action failed: ${kind}`);
    } finally { setBusy(""); }
  }

  return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
    <div className="mx-auto max-w-6xl space-y-6">
      <header>
        <div className="text-[10px] uppercase tracking-[.2em] text-[#7890a8]">Cyclothone / Protective Intelligence</div>
        <h1 className="mt-2 text-2xl font-semibold">Executive Protection</h1>
        <p className="mt-1 max-w-3xl text-xs text-[#91a0b2]">Time-bound assignments, independent approval, regional public-threat matching and audited SOS incidents. This workspace does not collect live personal location.</p>
      </header>
      {error && <ServiceError message={error}/>}
      <section className="space-y-4 border border-[#1a2736] bg-[#0a0f16] p-5">
        <div><h2 className="text-sm font-semibold">Create assignment</h2><p className="mt-1 text-xs text-[#738398]">Requires consent evidence and a separate approver. Maximum duration: 14 days.</p></div>
        <div className="grid gap-3 md:grid-cols-2">
          <input value={name} onChange={e=>setName(e.target.value)} placeholder="Assignment name" className="border border-[#263548] bg-[#05080d] p-3 text-xs"/>
          <input value={region} onChange={e=>setRegion(e.target.value)} placeholder="Region code (e.g. GB-LON)" className="border border-[#263548] bg-[#05080d] p-3 text-xs"/>
          <input value={subjectRef} onChange={e=>setSubjectRef(e.target.value)} placeholder="Opaque principal reference (hashed before storage)" className="border border-[#263548] bg-[#05080d] p-3 text-xs"/>
          <input value={authorizationRef} onChange={e=>setAuthorizationRef(e.target.value)} placeholder="Authorization reference" className="border border-[#263548] bg-[#05080d] p-3 text-xs"/>
          <input value={consentHash} onChange={e=>setConsentHash(e.target.value)} placeholder="Consent evidence SHA-256" className="border border-[#263548] bg-[#05080d] p-3 text-xs md:col-span-2"/>
          <input value={start} onChange={e=>setStart(e.target.value)} type="datetime-local" className="border border-[#263548] bg-[#05080d] p-3 text-xs"/>
          <input value={end} onChange={e=>setEnd(e.target.value)} type="datetime-local" className="border border-[#263548] bg-[#05080d] p-3 text-xs"/>
          <textarea value={purpose} onChange={e=>setPurpose(e.target.value)} rows={2} placeholder="Specific protective purpose" className="border border-[#263548] bg-[#05080d] p-3 text-xs md:col-span-2"/>
        </div>
        <button disabled={busy==="create"} onClick={()=>void create()} className="border border-[#31506d] bg-[#102033] px-4 py-2 text-[10px] uppercase tracking-[.12em] disabled:opacity-40">{busy==="create"?"Creating…":"Create pending assignment"}</button>
      </section>
      <section className="space-y-3">
        <div className="flex items-center justify-between"><h2 className="text-sm font-semibold">Assignments</h2><button onClick={()=>void load()} className="text-[10px] text-[#8ba4be]">Refresh</button></div>
        {loading ? <ServiceLoading/> : items.length===0 ? <div className="border border-[#1a2736] bg-[#0a0f16] p-5 text-xs text-[#8291a3]">No assignments found.</div> : items.map(item=><article key={item.id} className="space-y-3 border border-[#1a2736] bg-[#0a0f16] p-4">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div><div className="text-sm font-medium">{item.assignment_name}</div><div className="mt-1 text-[10px] text-[#8494a8]">{item.region_code} · {fmt(item.start_time)} — {fmt(item.end_time)}</div><div className="mt-1 text-xs text-[#a7b4c4]">{item.purpose}</div></div>
            <span className="border border-[#29394b] px-2 py-1 text-[9px] uppercase tracking-[.12em] text-[#a8bbcf]">{item.status}</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {item.status==="pending_approval" && <button disabled={busy===item.id+":approve"} onClick={()=>void action(item.id,"approve")} className="border border-[#31506d] px-3 py-2 text-[9px] uppercase">Approve (second person)</button>}
            {item.status==="active" && <>
              <input value={findingIds[item.id]||""} onChange={e=>setFindingIds(p=>({...p,[item.id]:e.target.value}))} placeholder="Tenant threat finding IDs (comma-separated)" className="min-w-[240px] flex-1 border border-[#263548] bg-[#05080d] px-3 py-2 text-[10px]"/>
              <button disabled={busy===item.id+":correlate"} onClick={()=>void action(item.id,"correlate")} className="border border-[#31506d] px-3 py-2 text-[9px] uppercase">Match public threats</button>
              <button disabled={busy===item.id+":sos"} onClick={()=>void action(item.id,"sos")} className="border border-[#754044] px-3 py-2 text-[9px] uppercase text-[#ffb5b5]">Raise SOS</button>
              <button disabled={busy===item.id+":close"} onClick={()=>void action(item.id,"close")} className="border border-[#4a5360] px-3 py-2 text-[9px] uppercase">Close & purge</button>
            </>}
          </div>
          {results[item.id] && <pre className="overflow-auto border border-[#202d3c] bg-[#05080d] p-3 text-[10px] text-[#a9bdd1]">{JSON.stringify(results[item.id],null,2)}</pre>}
        </article>)}
      </section>
      <p className="text-[10px] text-[#68798c]">SOS records a P1 incident for a human response. It does not dispatch authorities or change camera, door or other physical-device state.</p>
    </div>
  </main>;
}
