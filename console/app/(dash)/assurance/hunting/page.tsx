"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function Hunting(){
  const [hunts,setHunts]=useState<Row[]>([]),[runs,setRuns]=useState<Row[]>([]);
  const [query,setQuery]=useState(""),[result,setResult]=useState<Row|null>(null);
  const [loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState("");
  async function load(){setLoading(true);setError("");try{const [h,r]=await Promise.all([apiFetch<unknown>("/api/v1/hunts/"),apiFetch<unknown>("/api/v1/hunts/runs/history")]);setHunts(Array.isArray(h)?h:[]);setRuns(Array.isArray(r)?r:[])}catch(e){setError(e instanceof Error?e.message:"Could not load hunting");}finally{setLoading(false)}}
  useEffect(()=>{void load()},[]);
  async function run(){if(!query.trim())return;setBusy(true);setError("");setResult(null);try{const r=await apiFetch<Row>("/api/v1/hunts/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:query.trim()})});setResult(r);await load()}catch(e){setError(e instanceof Error?e.message:"Hunt failed")}finally{setBusy(false)}}
  const resultCount=result?.count??result?.total??result?.matches??null;
  return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]"><div className="mx-auto max-w-6xl space-y-5">
    <header><h1 className="text-2xl font-semibold">Threat Hunting</h1><p className="mt-1 text-xs text-[#8a97a8]">Ask Cyclothone to look for a specific threat pattern in your available security data.</p></header>
    {error&&<ServiceError message={error}/>}
    <section className="border border-[#1a2330] bg-[#0a0e14] p-5"><div className="text-sm font-medium">What are you looking for?</div><p className="mt-1 text-xs text-[#687789]">Enter a supported hunting query. Cyclothone will return only data available to your organization.</p><textarea value={query} onChange={e=>setQuery(e.target.value)} rows={4} placeholder="Example: find repeated failed logins from one source" className="mt-4 w-full border border-[#2a3646] bg-[#030508] p-3 text-xs"/><button disabled={busy||!query.trim()} onClick={()=>void run()} className="mt-3 border border-[#2a394d] bg-[#0b1118] px-4 py-2 text-[10px] uppercase tracking-[.12em] disabled:opacity-40">{busy?"Searching…":"Start hunt"}</button></section>
    {result&&<section className="border border-[#1a2330] bg-[#0a0e14] p-5"><div className="text-sm font-medium">Result</div><p className="mt-1 text-xs text-[#687789]">{resultCount!==null?String(resultCount)+" matching result(s) returned.":"The hunt completed and returned a result."}</p><div className="mt-4 grid gap-2 sm:grid-cols-2">{Object.entries(result).filter(([k])=>!["query","results","matches"].includes(k)).slice(0,8).map(([k,v])=><div key={k} className="border border-[#141d28] p-3"><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{k.replaceAll("_"," ")}</div><div className="mt-1 break-words text-xs">{typeof v==="string"||typeof v==="number"||typeof v==="boolean"?String(v):Array.isArray(v)?v.length+" items":"Available"}</div></div>)}</div></section>}
    {loading?<ServiceLoading/>:<section className="border border-[#1a2330] bg-[#0a0e14] p-5"><div className="flex justify-between"><div><div className="text-sm font-medium">Hunting activity</div><div className="text-xs text-[#687789]">Saved hunts and previous runs.</div></div><span className="text-xs text-[#687789]">{runs.length} runs</span></div>{hunts.length===0&&runs.length===0?<ServiceEmpty title="No hunting activity yet" detail="Start a hunt above to create the first real run."/>:<div className="mt-4 space-y-2">{runs.slice(0,10).map((r,i)=><div key={String(r.id??i)} className="flex items-center gap-3 border border-[#141d28] p-3"><span className="mr-auto text-xs">{String(r.status??"Run")}</span><span className="text-[10px] text-[#687789]">{String(r.started_at??"")}</span></div>)}</div>}</section>}
  </div></main>
}
