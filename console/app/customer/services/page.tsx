"use client";

import { useEffect, useMemo, useState } from "react";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, setApiToken, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../lib/api";

type Service={key:string;name:string;description:string;outcome:string;accent:string};
const SERVICES:Service[]=[
["cybersecurity_assessment","Cybersecurity Assessment","Assess exposure, controls and security posture.","Verified findings and remediation guidance.","#5ccbc3"],
["incident_response","Incident Response","Coordinate an active or suspected security incident.","Case activity and documented outcome.","#ff3d67"],
["threat_intelligence","Threat Intelligence","Understand relevant threats, indicators and campaigns.","Verified intelligence and investigation pivots.","#ff5b64"],
["web_intelligence","Web Intelligence","Monitor approved web targets for relevant activity.","Verified web findings and status.","#39d7ff"],
["scam_monitoring","Scam Monitoring","Identify scam signals affecting people, brands or channels.","Verified signals and response recommendations.","#ffb52e"],
["dark_web_monitoring","Dark Web Monitoring","Monitor approved sources for organizational exposure.","Verified exposure and case activity.","#9b6cff"],
["brand_protection","Brand Protection","Detect impersonation, abuse and threats to brand assets.","Verified threats and response activity.","#ff9d32"],
["soc_mdr","SOC / MDR","Operate continuous security monitoring and detection workflows.","Security cases and operational results.","#6de7a1"],
["ai_security","AI Security","Assess and monitor AI systems and AI-related exposure.","Governed findings, controls and results.","#3c9dff"],
["physical_security","Physical Security","Monitor authorized physical and location security signals.","Verified physical findings and case activity.","#ffd34e"],
["compliance","Compliance","Measure security controls against required frameworks.","Assurance status, evidence and findings.","#54e38a"],
["hunting","Threat Hunting","Test authorized hypotheses beyond existing alerts.","Hunt status, findings and resulting cases.","#ff8a3d"],
["investigation","Investigation","Connect authorized evidence into a defensible investigation.","Evidence and documented outcome.","#4aa8ff"],
["recovery","Recovery","Restore trusted operation through the approved recovery workflow.","Recovery status and verified result.","#55e6a1"],
["mobile_digital_intelligence","Mobile & Digital Intelligence","Authorized mobile, device, network, location and RF intelligence.","Verified provider observations and controlled investigation.","#38a8ff"]
].map(([key,name,description,outcome,accent])=>({key,name,description,outcome,accent})) as Service[];

const statusTone:Record<string,string>={approved:"text-[#9ff5c0]",resolved:"text-[#9ff5c0]",closed:"text-[#9ff5c0]",pending:"text-[#ffd27a]",submitted:"text-[#ffd27a]",in_progress:"text-[#ffd27a]",rejected:"text-[#ff7c93]"};

export default function CustomerServices(){
 const [orgs,setOrgs]=useState<CustomerOrganization[]>([]),[requests,setRequests]=useState<CustomerServiceRequest[]>([]),[cases,setCases]=useState<CustomerCase[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
 async function load(){setLoading(true);setError("");try{const[o,r,c]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests(),getCustomerCases()]);setOrgs(o.organizations);setRequests(r.service_requests);setCases(c.cases)}catch(e){setError(e instanceof Error?e.message:"Unable to load customer services")}finally{setLoading(false)}}
 useEffect(()=>{setApiToken(sessionStorage.getItem("cyclothone_access_token")||"");void load()},[]);
 const org=orgs[0]??null;
 const requestCounts=useMemo(()=>requests.reduce<Record<string,number>>((m,r)=>(m[r.service_key]=(m[r.service_key]??0)+1,m),{}),[requests]);
 const caseCounts=useMemo(()=>cases.reduce<Record<string,number>>((m,c)=>{const k=c.service_request?.service_key;if(k)m[k]=(m[k]??0)+1;return m},{}),[cases]);
 return <main className="cyclo-water min-h-screen overflow-hidden text-[#e8f1f3]">
  <header className="relative z-10 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 bg-[#02090e]/70 px-5 py-4 backdrop-blur-2xl">
   <div className="flex items-center gap-3"><a href="/customer/overview" className="cyclo-mark text-lg font-bold">◌</a><div><a href="/customer/overview" className="font-semibold tracking-tight">CYCLOTHONE</a><span className="ml-3 text-[9px] uppercase tracking-[.18em] text-[#789aa4]">Customer</span></div></div>
   <nav className="flex flex-wrap gap-2 text-[10px]"><a href="/customer/overview" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Overview</a><a href="/customer/services" className="cyclo-pill px-3 py-2 text-[#c2f35a]">Services</a><a href="/customer/cases" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Cases</a><a href="/customer/profile" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Profile</a></nav>
  </header>
  <div className="relative z-10 mx-auto max-w-7xl px-5 py-10 md:px-8">
   <div className="flex max-w-5xl items-end justify-between gap-6"><div><div className="text-[9px] uppercase tracking-[.22em] text-[#4f8494]">Security beneath the surface</div><h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-5xl">Choose what you need protected.</h1><p className="mt-4 max-w-3xl text-sm leading-7 text-[#8ca6ad]">Explore every Cyclothone capability before creating a protected request. Each service follows its own operational path and returns evidence, status and a defensible result.</p></div><div className="cyclo-orb hidden h-20 w-20 shrink-0 md:block"/></div>
   {error&&<div className="mt-7 rounded-2xl border border-[#ff3d67]/30 bg-[#250910]/50 p-4 text-xs text-[#ff8ba0]">{error}</div>}
   {!loading&&<div className="mt-9 flex flex-wrap items-center justify-between gap-3"><div className="text-xs text-[#69858d]"><span className="text-[#c2f35a]">{SERVICES.length}</span> live service surfaces</div>{org?<div className="cyclo-pill px-4 py-2 text-[10px] text-[#9ff5c0]">{org.legal_name} · {org.admission_status}</div>:<a href="/customer/profile" className="cyclo-pill px-4 py-2 text-[10px] text-[#c2f35a]">Create organization when ready →</a>}</div>}
   {loading?<div className="mt-8 p-10 text-center text-xs text-[#69858d]">Reading live service status…</div>:<div className="mt-7 grid gap-5 md:grid-cols-2 xl:grid-cols-3">{SERVICES.map((s,i)=>{const count=requestCounts[s.key]??0;const cc=caseCounts[s.key]??0;const latest=requests.filter(r=>r.service_key===s.key).sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)))[0];return <a key={s.key} href={"/customer/services/"+encodeURIComponent(s.key)} className="cyclo-node group min-h-[290px] p-6 shadow-[0_24px_80px_rgba(0,0,0,.22)]">
    <div className="relative z-10 flex items-start justify-between gap-4"><div><div className="font-mono text-[9px] text-[#4e707b]">{String(i+1).padStart(2,"0")} / SERVICE</div><h2 className="mt-2 text-lg font-medium">{s.name}</h2></div>{latest&&<span className={"text-[9px] uppercase tracking-wider "+(statusTone[latest.status]??"text-[#789aa4]")}>{latest.status.replaceAll("_"," ")}</span>}</div>
    <p className="relative z-10 mt-5 text-xs leading-6 text-[#8ca6ad]">{s.description}</p>
    <div className="relative z-10 mt-5 flex items-center gap-2 text-[9px] uppercase tracking-[.14em]" style={{color:s.accent}}><span className="cyclo-signal">●</span> {s.outcome}</div>
    <div className="relative z-10 mt-6 flex items-end justify-between"><span className="text-[10px] text-[#59747d]">{org?count+" request"+(count===1?"":"s")+" · "+cc+" case"+(cc===1?"":"s"):"Explore the workflow"}</span><span className="text-xl text-[#c2f35a] transition-transform group-hover:translate-x-1">↗</span></div>
   </a>})}</div>}
  </div>
 </main>
}