"use client";

import { useEffect,useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceError,ServiceLoading,ServiceSection } from "../../../../components/ServiceData";
type Data=Record<string,unknown>;
export default function RecoveryPage(){
 const [data,setData]=useState<Data|null>(null),[loading,setLoading]=useState(true),[error,setError]=useState("");
 useEffect(()=>{void(async()=>{setLoading(true);setError("");try{setData(await apiFetch<Data>("/api/v1/assurance/recovery"))}catch(e){setError(e instanceof Error?e.message:"Recovery is not available yet")}finally{setLoading(false)}})()},[]);
 const status=String(data?.status??data?.state??"Unavailable");
 return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]"><div className="mx-auto max-w-5xl space-y-5">
  <header><h1 className="text-2xl font-semibold">Recovery</h1><p className="mt-1 text-xs text-[#8a97a8]">Check whether your organization is ready to recover protected systems and data.</p></header>
  {loading?<ServiceLoading/>:<>{error?<ServiceError message={error}/>:<ServiceSection title="Recovery status"><div className="text-lg font-medium">{status}</div><p className="mt-2 text-xs text-[#687789]">{status==="Unavailable"?"Recovery controls are not currently available.":"Cyclothone is reporting the current recovery state for your organization."}</p>{data&&<div className="mt-4 grid gap-2 sm:grid-cols-2">{Object.entries(data).filter(([k])=>k!=="status"&&k!=="state").slice(0,6).map(([k,v])=><div key={k} className="border border-[#141d28] p-3"><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{k.replaceAll("_"," ")}</div><div className="mt-1 break-words text-xs">{typeof v==="string"||typeof v==="number"||typeof v==="boolean"?String(v):"Available"}</div></div>)}</div>}</ServiceSection>}</>}
 </div></main>
}