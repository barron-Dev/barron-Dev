"use client";
import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useRouter } from "next/navigation";
import { getCustomerOrganizations, getCustomerVerification, setApiToken, apiFetch, type CustomerOrganization } from "../../lib/api";

const SERVICES=[["cybersecurity_assessment","Cybersecurity Assessment"],["incident_response","Incident Response"],["threat_intelligence","Threat Intelligence"],["web_intelligence","Web Intelligence"],["scam_monitoring","Scam Monitoring"],["dark_web_monitoring","Dark Web Monitoring"],["brand_protection","Brand Protection"],["soc_mdr","SOC / MDR"],["ai_security","AI Security"],["physical_security","Physical Security"],["compliance","Compliance"],["hunting","Threat Hunting"],["investigation","Investigation"],["recovery","Recovery"]];

export default function RequestService(){
 const router=useRouter();
 const [orgs,setOrgs]=useState<CustomerOrganization[]>([]),[org,setOrg]=useState(""),[service,setService]=useState("cybersecurity_assessment"),[urgency,setUrgency]=useState("normal"),[description,setDescription]=useState(""),[verification,setVerification]=useState<any[]>([]),[error,setError]=useState<string|null>(null),[ok,setOk]=useState(false),[loading,setLoading]=useState(true);
 async function load(){
  setLoading(true);setError(null);
  try{const r=await getCustomerOrganizations();setOrgs(r.organizations);const id=r.organizations[0]?.id||"";setOrg(id);if(id){const v=await getCustomerVerification(id);setVerification(v.verifications)}}catch(e){setError(e instanceof Error?e.message:"Unable to load organization")}finally{setLoading(false)}
 }
 useEffect(()=>{const requested=new URLSearchParams(window.location.search).get("service"); if(requested && SERVICES.some(x=>x[0]===requested)) setService(requested); const t=sessionStorage.getItem("cyclothone_access_token")||"";if(!t){router.replace("/login");return}setApiToken(t);void load()},[]);
 async function selectOrg(id:string){setOrg(id);setError(null);try{const v=await getCustomerVerification(id);setVerification(v.verifications)}catch(e){setError(e instanceof Error?e.message:"Unable to load verification")}}
 async function requestAdmission(){setError(null);try{await apiFetch("/api/v1/customer/organizations/"+encodeURIComponent(org)+"/admission",{method:"POST"});await load()}catch(e){setError(e instanceof Error?e.message:"Admission request failed")}}
 async function submit(e:FormEvent){e.preventDefault();setError(null);setOk(false);try{await apiFetch("/api/v1/customer/service-requests",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({organization_id:org,service_key:service,urgency,description})});setOk(true);setDescription("")}catch(e){setError(e instanceof Error?e.message:"Service request failed")}}
 const current=orgs.find(x=>x.id===org);
 const body: ReactNode = loading ? (
  <div className="mt-8 border border-white/10 p-6 text-xs text-[#688487]">Loading organization…</div>
 ) : !orgs.length ? (
  <div className="mt-8 rounded-[2rem] border border-dashed border-white/10 p-8 text-center text-xs text-[#688487]">No organization is available. <a className="text-[#5ccbc3]" href="/register">Create one</a>.</div>
 ) : (
  <form onSubmit={submit} className="mt-8 space-y-5 rounded-[2rem] border border-white/10 bg-[#06181e]/65 p-6 shadow-[0_30px_100px_rgba(0,0,0,.3)] backdrop-blur-xl">
   <label className="block text-sm">Organization<select required value={org} onChange={e=>void selectOrg(e.target.value)} className="mt-2 w-full rounded-[1.25rem] border border-white/10 bg-[#041319]/80 p-3.5 outline-none focus:border-[#4fc4bd]/40">{orgs.map(o=><option key={o.id} value={o.id}>{o.legal_name} · {o.admission_status}</option>)}</select></label>
   <div className="border border-white/10 p-3 text-xs text-[#91aaab]">Admission: <strong className="text-[#e8eef6]">{current?.admission_status}</strong> · Verification: <strong className="text-[#e8eef6]">{current?.verification_status}</strong>{current?.admission_status !== "approved" && <div className="mt-3 text-[#ffd27a]">Your workspace must be admitted before a service request can be created. <a href="/customer/workspace" className="text-[#5ccbc3]">View workspace</a></div>}</div>
   <div className="border border-white/10 p-3 text-xs text-[#91aaab]">Verification records: {verification.length ? verification.map(v=>v.verification_type+":"+v.status).join(" · ") : "none"}</div>
   <label className="block text-sm">Service<select value={service} onChange={e=>setService(e.target.value)} className="mt-2 w-full rounded-[1.25rem] border border-white/10 bg-[#041319]/80 p-3.5 outline-none focus:border-[#4fc4bd]/40">{SERVICES.map(x=><option key={x[0]} value={x[0]}>{x[1]}</option>)}</select></label>
   <label className="block text-sm">Urgency<select value={urgency} onChange={e=>setUrgency(e.target.value)} className="mt-2 w-full rounded-[1.25rem] border border-white/10 bg-[#041319]/80 p-3.5 outline-none focus:border-[#4fc4bd]/40">{["low","normal","high","critical"].map(x=><option key={x}>{x}</option>)}</select></label>
   <label className="block text-sm">Requirement<textarea required minLength={10} maxLength={10000} value={description} onChange={e=>setDescription(e.target.value)} rows={7} className="mt-2 w-full rounded-[1.25rem] border border-white/10 bg-[#041319]/80 p-3.5 outline-none focus:border-[#4fc4bd]/40" placeholder="Describe what you need Cyclothone to secure, investigate, monitor, or assess."/></label>
   {ok&&<div className="border border-[#00e07a]/30 p-3 text-sm text-[#7df0ad]">Service request submitted.</div>}
   <button disabled={!org||current?.admission_status !== "approved"} className="w-full rounded-full border border-[#5ccbc3]/50 bg-[#2b9b96] p-3.5 text-white shadow-[0_14px_35px_rgba(43,155,150,.18)] disabled:opacity-40">Submit service request</button>
  </form>
 );
 return (
  <main className="relative min-h-screen overflow-hidden min-h-screen bg-[#021014] text-[#e8eef6]">
   <header className="relative z-10 backdrop-blur-2xl flex items-center justify-between border-b border-white/10 bg-[#06181e]/70 px-6 py-4"><a href="/customer/services" className="font-semibold">Cyclothone</a><div className="flex gap-3 text-xs"><a href="/customer/services" className="text-[#5ccbc3]">Services</a><a href="/customer/workspace" className="text-[#91aaab]">Customer workspace</a></div></header>
   <div className="relative z-10 mx-auto max-w-3xl px-6 py-10 md:py-14">
    <h1 className="text-3xl font-semibold">Request a security service</h1>
    <p className="mt-2 text-sm text-[#91aaab]">Tell us the outcome you need. Cyclothone will route the request through the appropriate security workflow.</p>
    {error&&<div className="mt-5 border border-[#ff2d55]/40 p-3 text-sm text-[#ff6b83]">{error}</div>}
    {body}
   </div>
  </main>
 );
}
