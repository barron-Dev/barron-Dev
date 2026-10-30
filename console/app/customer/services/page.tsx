"use client";

import { useEffect, useMemo, useState } from "react";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, setApiToken, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../lib/api";

type Service={key:string;name:string;description:string;outcome:string;status:"available"|"in_development";accent:string};
const SERVICES:Service[]=[
  {key:"cybersecurity_assessment",name:"Cybersecurity Assessment",description:"Check a website for real security exposure and surface-level weaknesses.",outcome:"A live assessment with findings, evidence and clear next steps.",status:"available",accent:"#5ccbc3"},
  {key:"dark_web_monitoring",name:"Dark Web Monitoring",description:"Monitor a domain for real exposure signals from configured external sources.",outcome:"A live monitoring result with persisted findings, alerts and evidence.",status:"available",accent:"#c2f35a"},
  {key:"brand_protection",name:"Brand Protection",description:"Protect brand identity and digital properties by identifying impersonation, fraudulent domains and brand-abuse signals.",outcome:"Service build visibility is available now. Operational monitoring and evidence workflows are still being completed.",status:"in_development",accent:"#d7a94e"},
  {key:"ai_security",name:"AI Security",description:"Assess AI models, agents, applications and deployments for security and execution risks.",outcome:"Service build visibility is available now. The production assessment and evidence workflow is still being completed.",status:"in_development",accent:"#a78bfa"}
];

const statusTone:Record<string,string>={approved:"text-[#9ff5c0]",resolved:"text-[#9ff5c0]",closed:"text-[#9ff5c0]",pending:"text-[#ffd27a]",submitted:"text-[#ffd27a]",in_progress:"text-[#ffd27a]",rejected:"text-[#ff7c93]"};

export default function CustomerServices(){
 const [orgs,setOrgs]=useState<CustomerOrganization[]>([]),[requests,setRequests]=useState<CustomerServiceRequest[]>([]),[cases,setCases]=useState<CustomerCase[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
 async function load(){setLoading(true);setError("");try{const[o,r,c]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests(),getCustomerCases()]);setOrgs(o.organizations);setRequests(r.service_requests);setCases(c.cases)}catch(e){setError(e instanceof Error?e.message:"Unable to load services")}finally{setLoading(false)}}
 useEffect(()=>{setApiToken(sessionStorage.getItem("cyclothone_access_token")||"");void load()},[]);
 const org=orgs[0]??null;
 const requestCount=(key:string)=>requests.filter(r=>r.service_key===key).length;
 const caseCount=(key:string)=>cases.filter(c=>c.service_request?.service_key===key).length;
 return <main className="cyclo-water min-h-screen overflow-hidden text-[#e8f1f3]">
  <header className="relative z-10 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 bg-[#02090e]/70 px-5 py-4 backdrop-blur-2xl">
   <div className="flex items-center gap-3"><a href="/customer/overview" className="cyclo-mark text-lg font-bold">◌</a><div><a href="/customer/overview" className="font-semibold tracking-tight">CYCLOTHONE</a><span className="ml-3 text-[9px] uppercase tracking-[.18em] text-[#789aa4]">Customer</span></div></div>
   <nav className="flex flex-wrap gap-2 text-[10px]"><a href="/customer/overview" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Overview</a><a href="/customer/services" className="cyclo-pill px-3 py-2 text-[#c2f35a]">Services</a><a href="/customer/cases" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Cases</a><a href="/customer/profile" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Profile</a></nav>
  </header>
  <div className="relative z-10 mx-auto max-w-6xl px-5 py-10 md:px-8">
   <div className="max-w-3xl"><div className="text-[9px] uppercase tracking-[.22em] text-[#4f8494]">Discover. Understand. Protect.</div><h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-5xl">Start with what you need checked.</h1><p className="mt-4 text-sm leading-7 text-[#9ab0b6]">Explore active Cyclothone services and see which capabilities are currently being built. An in-development service is visible for planning, but cannot accept operational requests yet.</p></div>
   {error&&<div className="mt-7 rounded-2xl border border-[#ff3d67]/30 bg-[#250910]/50 p-4 text-xs text-[#ff8ba0]">{error}</div>}
   {!loading&&<div className="mt-8 flex flex-wrap items-center justify-between gap-3 text-xs"><span className="text-[#69858d]">{SERVICES.filter(s=>s.status==="available").length} operational · {SERVICES.filter(s=>s.status==="in_development").length} in development</span>{org&&<span className="cyclo-pill px-4 py-2 text-[10px] text-[#9ff5c0]">{org.legal_name}</span>}</div>}
   {loading?<div className="mt-8 p-10 text-center text-xs text-[#69858d]">Loading services…</div>:<div className="mt-7 grid gap-5 md:grid-cols-2">
    {SERVICES.map(service=>{
      const latest=requests.filter(r=>r.service_key===service.key).sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)))[0];
      const href=service.status==="available"?(service.key==="cybersecurity_assessment"?"/customer/services/cybersecurity_assessment":"/request-service?service="+service.key):"/request-service?service="+service.key;
      return <a key={service.key} href={href} className="group relative block overflow-hidden rounded-[2rem] border border-white/[0.12] bg-white/[0.045] px-7 py-8 shadow-[0_20px_70px_rgba(0,0,0,.18)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5 hover:border-white/20 hover:bg-white/[0.065]">
       <div className="absolute -right-16 -top-16 h-40 w-40 rounded-full blur-3xl" style={{backgroundColor:service.accent+"18"}}/>
       <div className="relative z-10 flex items-start justify-between gap-4"><div className="font-mono text-[9px] uppercase tracking-[.15em]" style={{color:service.accent}}>{service.status==="available"?"Operational service":"In development"}</div>{latest&&<span className={"text-[9px] uppercase tracking-wider "+(statusTone[latest.status]??"text-[#789aa4]")}>{latest.status.replaceAll("_"," ")}</span>}</div>
       <h2 className="relative z-10 mt-3 text-2xl font-medium">{service.name}</h2>
       <p className="relative z-10 mt-4 text-sm leading-7 text-[#9ab0b6]">{service.description}</p>
       <div className="relative z-10 mt-6 border-t border-white/10 pt-5"><div className="text-[9px] uppercase tracking-[.16em] text-[#4e707b]">Service outcome</div><p className="mt-2 text-xs leading-6 text-[#9ab0b6]">{service.outcome}</p></div>
       <div className="relative z-10 mt-6 flex items-center justify-between"><span className="text-[10px] text-[#59747d]">{requestCount(service.key)} requests · {caseCount(service.key)} cases</span><span className="text-[10px]" style={{color:service.accent}}>{service.status==="available"?"Open service →":"View build status →"}</span></div>
      </a>;
    })}
   </div>}
  </div>
 </main>
}
