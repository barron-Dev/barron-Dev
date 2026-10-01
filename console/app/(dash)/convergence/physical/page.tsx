"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading } from "../../../../components/ServiceData";
type Row=Record<string,unknown>;
export default function PhysicalPage(){
 const [sites,setSites]=useState<Row[]>([]),[correlations,setCorrelations]=useState<Row[]>([]);
 const [loading,setLoading]=useState(true),[error,setError]=useState("");
 async function load(){setLoading(true);setError("");try{const [s,c]=await Promise.all([apiFetch<Row[]>("/api/v1/physical/sites"),apiFetch<Row[]>("/api/v1/physical/correlations")]);setSites(Array.isArray(s)?s:[]);setCorrelations(Array.isArray(c)?c:[])}catch(e){setError(e instanceof Error?e.message:"Could not load physical security")}finally{setLoading(false)}}
 useEffect(()=>{void load()},[]);
 return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]"><div className="mx-auto max-w-6xl space-y-5">
  <header><h1 className="text-2xl font-semibold">Physical Security</h1><p className="mt-1 text-xs text-[#8a97a8]">See physical security activity connected to your organization.</p></header>
  {error&&<ServiceError message={error}/>}
  {loading?<ServiceLoading/>:<>
   <section className="border border-[#1a2330] bg-[#0a0e14] p-5"><div className="text-sm font-medium">Your sites</div><p className="mt-1 text-xs text-[#687789]">Locations currently connected to Cyclothone.</p>{sites.length===0?<ServiceEmpty title="No sites connected" detail="Connect a physical-security site before activity can be shown."/>:<div className="mt-4 grid gap-2 sm:grid-cols-2">{sites.map((s,i)=><div key={String(s.id??i)} className="border border-[#141d28] p-4"><div className="text-sm">{String(s.name??"Site")}</div><div className="mt-1 text-xs text-[#687789]">{String(s.country??"")} {s.status?"· "+String(s.status):""}</div></div>)}</div>}</section>
   <section className="border border-[#1a2330] bg-[#0a0e14] p-5"><div className="flex justify-between"><div><div className="text-sm font-medium">Security activity</div><div className="text-xs text-[#687789]">Physical events correlated with digital security information.</div></div><span className="text-xs text-[#687789]">{correlations.length}</span></div>{correlations.length===0?<ServiceEmpty title="No activity yet" detail="No physical-security correlations are currently available."/>:<div className="mt-4 space-y-2">{correlations.slice(0,20).map((c,i)=><div key={String(c.id??i)} className="flex items-center gap-3 border border-[#141d28] p-3"><span className="mr-auto text-xs">{String(c.correlation_type??"Security event")}</span><span className="text-[10px] text-[#687789]">{String(c.severity??"")} · {String(c.status??"")}</span></div>)}</div>}</section>
  </>}
 </div></main>
}